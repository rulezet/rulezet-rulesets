rule TTP_XOR_MULT_DOSStub_dc0d {
  strings:
    $key_dc0d = { 88 65 [2] fc 7d [2] bb 7f [2] fc 6e [2] b2 62 [2] be 68 [2] a9 63 [2] b2 2d [2] 8f }

  condition:
    any of them
}