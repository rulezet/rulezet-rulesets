rule TTP_XOR_MULT_DOSStub_dc7d {
  strings:
    $key_dc7d = { 88 15 [2] fc 0d [2] bb 0f [2] fc 1e [2] b2 12 [2] be 18 [2] a9 13 [2] b2 5d [2] 8f }

  condition:
    any of them
}