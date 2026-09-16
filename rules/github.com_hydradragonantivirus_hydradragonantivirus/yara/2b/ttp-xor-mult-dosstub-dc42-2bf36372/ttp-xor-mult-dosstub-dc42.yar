rule TTP_XOR_MULT_DOSStub_dc42 {
  strings:
    $key_dc42 = { 88 2a [2] fc 32 [2] bb 30 [2] fc 21 [2] b2 2d [2] be 27 [2] a9 2c [2] b2 62 [2] 8f }

  condition:
    any of them
}