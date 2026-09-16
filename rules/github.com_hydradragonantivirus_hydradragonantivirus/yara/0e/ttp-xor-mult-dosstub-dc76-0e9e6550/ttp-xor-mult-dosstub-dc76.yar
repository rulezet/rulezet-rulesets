rule TTP_XOR_MULT_DOSStub_dc76 {
  strings:
    $key_dc76 = { 88 1e [2] fc 06 [2] bb 04 [2] fc 15 [2] b2 19 [2] be 13 [2] a9 18 [2] b2 56 [2] 8f }

  condition:
    any of them
}