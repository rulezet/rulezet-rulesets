rule TTP_XOR_MULT_DOSStub_584f {
  strings:
    $key_584f = { 0c 27 [2] 78 3f [2] 3f 3d [2] 78 2c [2] 36 20 [2] 3a 2a [2] 2d 21 [2] 36 6f [2] 0b }

  condition:
    any of them
}