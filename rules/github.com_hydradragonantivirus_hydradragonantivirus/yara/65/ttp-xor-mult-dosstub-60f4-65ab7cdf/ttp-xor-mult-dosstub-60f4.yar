rule TTP_XOR_MULT_DOSStub_60f4 {
  strings:
    $key_60f4 = { 34 9c [2] 40 84 [2] 07 86 [2] 40 97 [2] 0e 9b [2] 02 91 [2] 15 9a [2] 0e d4 [2] 33 }

  condition:
    any of them
}