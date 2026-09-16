rule TTP_XOR_MULT_DOSStub_1252 {
  strings:
    $key_1252 = { 46 3a [2] 32 22 [2] 75 20 [2] 32 31 [2] 7c 3d [2] 70 37 [2] 67 3c [2] 7c 72 [2] 41 }

  condition:
    any of them
}