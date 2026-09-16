rule TTP_XOR_MULT_DOSStub_2a52 {
  strings:
    $key_2a52 = { 7e 3a [2] 0a 22 [2] 4d 20 [2] 0a 31 [2] 44 3d [2] 48 37 [2] 5f 3c [2] 44 72 [2] 79 }

  condition:
    any of them
}