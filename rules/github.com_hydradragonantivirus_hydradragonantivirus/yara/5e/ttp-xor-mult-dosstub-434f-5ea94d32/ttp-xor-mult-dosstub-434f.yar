rule TTP_XOR_MULT_DOSStub_434f {
  strings:
    $key_434f = { 17 27 [2] 63 3f [2] 24 3d [2] 63 2c [2] 2d 20 [2] 21 2a [2] 36 21 [2] 2d 6f [2] 10 }

  condition:
    any of them
}