rule TTP_XOR_MULT_DOSStub_40f8 {
  strings:
    $key_40f8 = { 14 90 [2] 60 88 [2] 27 8a [2] 60 9b [2] 2e 97 [2] 22 9d [2] 35 96 [2] 2e d8 [2] 13 }

  condition:
    any of them
}