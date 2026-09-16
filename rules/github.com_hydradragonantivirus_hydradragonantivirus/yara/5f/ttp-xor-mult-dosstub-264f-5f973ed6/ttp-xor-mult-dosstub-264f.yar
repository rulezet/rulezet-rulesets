rule TTP_XOR_MULT_DOSStub_264f {
  strings:
    $key_264f = { 72 27 [2] 06 3f [2] 41 3d [2] 06 2c [2] 48 20 [2] 44 2a [2] 53 21 [2] 48 6f [2] 75 }

  condition:
    any of them
}