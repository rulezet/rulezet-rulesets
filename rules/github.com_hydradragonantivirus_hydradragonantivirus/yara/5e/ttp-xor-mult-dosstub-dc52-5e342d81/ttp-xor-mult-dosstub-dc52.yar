rule TTP_XOR_MULT_DOSStub_dc52 {
  strings:
    $key_dc52 = { 88 3a [2] fc 22 [2] bb 20 [2] fc 31 [2] b2 3d [2] be 37 [2] a9 3c [2] b2 72 [2] 8f }

  condition:
    any of them
}