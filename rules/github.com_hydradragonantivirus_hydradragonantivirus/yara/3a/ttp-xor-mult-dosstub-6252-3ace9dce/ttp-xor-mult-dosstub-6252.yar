rule TTP_XOR_MULT_DOSStub_6252 {
  strings:
    $key_6252 = { 36 3a [2] 42 22 [2] 05 20 [2] 42 31 [2] 0c 3d [2] 00 37 [2] 17 3c [2] 0c 72 [2] 31 }

  condition:
    any of them
}