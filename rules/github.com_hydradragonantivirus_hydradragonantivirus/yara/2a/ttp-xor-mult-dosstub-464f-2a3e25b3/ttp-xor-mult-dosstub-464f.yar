rule TTP_XOR_MULT_DOSStub_464f {
  strings:
    $key_464f = { 12 27 [2] 66 3f [2] 21 3d [2] 66 2c [2] 28 20 [2] 24 2a [2] 33 21 [2] 28 6f [2] 15 }

  condition:
    any of them
}