rule TTP_XOR_MULT_DOSStub_dc1d {
  strings:
    $key_dc1d = { 88 75 [2] fc 6d [2] bb 6f [2] fc 7e [2] b2 72 [2] be 78 [2] a9 73 [2] b2 3d [2] 8f }

  condition:
    any of them
}