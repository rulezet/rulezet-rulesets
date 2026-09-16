rule TTP_XOR_MULT_DOSStub_3a4f {
  strings:
    $key_3a4f = { 6e 27 [2] 1a 3f [2] 5d 3d [2] 1a 2c [2] 54 20 [2] 58 2a [2] 4f 21 [2] 54 6f [2] 69 }

  condition:
    any of them
}