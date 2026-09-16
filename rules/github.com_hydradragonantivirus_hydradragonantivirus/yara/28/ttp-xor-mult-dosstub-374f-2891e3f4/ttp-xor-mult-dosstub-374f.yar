rule TTP_XOR_MULT_DOSStub_374f {
  strings:
    $key_374f = { 63 27 [2] 17 3f [2] 50 3d [2] 17 2c [2] 59 20 [2] 55 2a [2] 42 21 [2] 59 6f [2] 64 }

  condition:
    any of them
}