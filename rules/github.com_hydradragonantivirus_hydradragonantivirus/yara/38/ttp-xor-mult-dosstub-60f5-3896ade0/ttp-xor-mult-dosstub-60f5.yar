rule TTP_XOR_MULT_DOSStub_60f5 {
  strings:
    $key_60f5 = { 34 9d [2] 40 85 [2] 07 87 [2] 40 96 [2] 0e 9a [2] 02 90 [2] 15 9b [2] 0e d5 [2] 33 }

  condition:
    any of them
}