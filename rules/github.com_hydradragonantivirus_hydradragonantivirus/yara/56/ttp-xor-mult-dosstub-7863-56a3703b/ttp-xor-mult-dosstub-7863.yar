rule TTP_XOR_MULT_DOSStub_7863 {
  strings:
    $key_7863 = { 2c 0b [2] 58 13 [2] 1f 11 [2] 58 00 [2] 16 0c [2] 1a 06 [2] 0d 0d [2] 16 43 [2] 2b }

  condition:
    any of them
}