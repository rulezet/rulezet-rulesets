rule TTP_XOR_MULT_DOSStub_5652 {
  strings:
    $key_5652 = { 02 3a [2] 76 22 [2] 31 20 [2] 76 31 [2] 38 3d [2] 34 37 [2] 23 3c [2] 38 72 [2] 05 }

  condition:
    any of them
}