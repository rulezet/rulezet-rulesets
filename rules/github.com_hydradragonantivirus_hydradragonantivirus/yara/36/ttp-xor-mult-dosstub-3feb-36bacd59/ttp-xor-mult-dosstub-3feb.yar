rule TTP_XOR_MULT_DOSStub_3feb {
  strings:
    $key_3feb = { 6b 83 [2] 1f 9b [2] 58 99 [2] 1f 88 [2] 51 84 [2] 5d 8e [2] 4a 85 [2] 51 cb [2] 6c }

  condition:
    any of them
}