rule TTP_XOR_MULT_DOSStub_1765 {
  strings:
    $key_1765 = { 43 0d [2] 37 15 [2] 70 17 [2] 37 06 [2] 79 0a [2] 75 00 [2] 62 0b [2] 79 45 [2] 44 }

  condition:
    any of them
}