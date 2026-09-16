rule TTP_XOR_MULT_DOSStub_1feb {
  strings:
    $key_1feb = { 4b 83 [2] 3f 9b [2] 78 99 [2] 3f 88 [2] 71 84 [2] 7d 8e [2] 6a 85 [2] 71 cb [2] 4c }

  condition:
    any of them
}