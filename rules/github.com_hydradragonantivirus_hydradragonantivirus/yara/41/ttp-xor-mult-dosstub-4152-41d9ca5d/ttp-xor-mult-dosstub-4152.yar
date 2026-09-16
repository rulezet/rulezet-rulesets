rule TTP_XOR_MULT_DOSStub_4152 {
  strings:
    $key_4152 = { 15 3a [2] 61 22 [2] 26 20 [2] 61 31 [2] 2f 3d [2] 23 37 [2] 34 3c [2] 2f 72 [2] 12 }

  condition:
    any of them
}