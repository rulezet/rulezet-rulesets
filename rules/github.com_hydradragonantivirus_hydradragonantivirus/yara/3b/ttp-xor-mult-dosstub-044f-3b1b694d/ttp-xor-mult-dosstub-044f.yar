rule TTP_XOR_MULT_DOSStub_044f {
  strings:
    $key_044f = { 50 27 [2] 24 3f [2] 63 3d [2] 24 2c [2] 6a 20 [2] 66 2a [2] 71 21 [2] 6a 6f [2] 57 }

  condition:
    any of them
}