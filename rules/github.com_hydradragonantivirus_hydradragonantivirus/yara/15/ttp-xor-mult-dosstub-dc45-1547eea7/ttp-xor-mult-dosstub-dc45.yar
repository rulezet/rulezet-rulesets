rule TTP_XOR_MULT_DOSStub_dc45 {
  strings:
    $key_dc45 = { 88 2d [2] fc 35 [2] bb 37 [2] fc 26 [2] b2 2a [2] be 20 [2] a9 2b [2] b2 65 [2] 8f }

  condition:
    any of them
}