rule TTP_XOR_MULT_DOSStub_3152 {
  strings:
    $key_3152 = { 65 3a [2] 11 22 [2] 56 20 [2] 11 31 [2] 5f 3d [2] 53 37 [2] 44 3c [2] 5f 72 [2] 62 }

  condition:
    any of them
}