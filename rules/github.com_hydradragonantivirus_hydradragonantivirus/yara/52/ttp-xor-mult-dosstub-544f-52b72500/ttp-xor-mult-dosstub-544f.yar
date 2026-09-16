rule TTP_XOR_MULT_DOSStub_544f {
  strings:
    $key_544f = { 00 27 [2] 74 3f [2] 33 3d [2] 74 2c [2] 3a 20 [2] 36 2a [2] 21 21 [2] 3a 6f [2] 07 }

  condition:
    any of them
}