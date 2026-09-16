rule TTP_XOR_MULT_DOSStub_60f2 {
  strings:
    $key_60f2 = { 34 9a [2] 40 82 [2] 07 80 [2] 40 91 [2] 0e 9d [2] 02 97 [2] 15 9c [2] 0e d2 [2] 33 }

  condition:
    any of them
}