rule TTP_XOR_MULT_DOSStub_004f {
  strings:
    $key_004f = { 54 27 [2] 20 3f [2] 67 3d [2] 20 2c [2] 6e 20 [2] 62 2a [2] 75 21 [2] 6e 6f [2] 53 }

  condition:
    any of them
}