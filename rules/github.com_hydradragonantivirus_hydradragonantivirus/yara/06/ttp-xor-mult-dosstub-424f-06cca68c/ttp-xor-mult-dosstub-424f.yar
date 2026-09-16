rule TTP_XOR_MULT_DOSStub_424f {
  strings:
    $key_424f = { 16 27 [2] 62 3f [2] 25 3d [2] 62 2c [2] 2c 20 [2] 20 2a [2] 37 21 [2] 2c 6f [2] 11 }

  condition:
    any of them
}