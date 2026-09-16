rule TTP_XOR_MULT_DOSStub_dc56 {
  strings:
    $key_dc56 = { 88 3e [2] fc 26 [2] bb 24 [2] fc 35 [2] b2 39 [2] be 33 [2] a9 38 [2] b2 76 [2] 8f }

  condition:
    any of them
}