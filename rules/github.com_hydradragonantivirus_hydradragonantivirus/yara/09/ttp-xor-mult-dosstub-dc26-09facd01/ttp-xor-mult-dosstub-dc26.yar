rule TTP_XOR_MULT_DOSStub_dc26 {
  strings:
    $key_dc26 = { 88 4e [2] fc 56 [2] bb 54 [2] fc 45 [2] b2 49 [2] be 43 [2] a9 48 [2] b2 06 [2] 8f }

  condition:
    any of them
}