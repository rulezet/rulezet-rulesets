rule TTP_XOR_MULT_DOSStub_dc4f {
  strings:
    $key_dc4f = { 88 27 [2] fc 3f [2] bb 3d [2] fc 2c [2] b2 20 [2] be 2a [2] a9 21 [2] b2 6f [2] 8f }

  condition:
    any of them
}