rule TTP_XOR_MULT_DOSStub_4452 {
  strings:
    $key_4452 = { 10 3a [2] 64 22 [2] 23 20 [2] 64 31 [2] 2a 3d [2] 26 37 [2] 31 3c [2] 2a 72 [2] 17 }

  condition:
    any of them
}