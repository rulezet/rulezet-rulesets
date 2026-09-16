rule TTP_XOR_MULT_DOSStub_40f2 {
  strings:
    $key_40f2 = { 14 9a [2] 60 82 [2] 27 80 [2] 60 91 [2] 2e 9d [2] 22 97 [2] 35 9c [2] 2e d2 [2] 13 }

  condition:
    any of them
}