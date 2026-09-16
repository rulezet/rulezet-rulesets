rule TTP_XOR_MULT_DOSStub_dc3d {
  strings:
    $key_dc3d = { 88 55 [2] fc 4d [2] bb 4f [2] fc 5e [2] b2 52 [2] be 58 [2] a9 53 [2] b2 1d [2] 8f }

  condition:
    any of them
}