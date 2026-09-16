rule TTP_XOR_MULT_DOSStub_0feb {
  strings:
    $key_0feb = { 5b 83 [2] 2f 9b [2] 68 99 [2] 2f 88 [2] 61 84 [2] 6d 8e [2] 7a 85 [2] 61 cb [2] 5c }

  condition:
    any of them
}