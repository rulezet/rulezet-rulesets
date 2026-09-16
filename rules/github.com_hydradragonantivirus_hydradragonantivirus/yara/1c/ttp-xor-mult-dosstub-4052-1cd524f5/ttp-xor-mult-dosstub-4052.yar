rule TTP_XOR_MULT_DOSStub_4052 {
  strings:
    $key_4052 = { 14 3a [2] 60 22 [2] 27 20 [2] 60 31 [2] 2e 3d [2] 22 37 [2] 35 3c [2] 2e 72 [2] 13 }

  condition:
    any of them
}