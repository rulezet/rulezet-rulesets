rule TTP_XOR_MULT_DOSStub_60f8 {
  strings:
    $key_60f8 = { 34 90 [2] 40 88 [2] 07 8a [2] 40 9b [2] 0e 97 [2] 02 9d [2] 15 96 [2] 0e d8 [2] 33 }

  condition:
    any of them
}