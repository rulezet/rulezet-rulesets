rule TTP_XOR_MULT_DOSStub_dc4e {
  strings:
    $key_dc4e = { 88 26 [2] fc 3e [2] bb 3c [2] fc 2d [2] b2 21 [2] be 2b [2] a9 20 [2] b2 6e [2] 8f }

  condition:
    any of them
}