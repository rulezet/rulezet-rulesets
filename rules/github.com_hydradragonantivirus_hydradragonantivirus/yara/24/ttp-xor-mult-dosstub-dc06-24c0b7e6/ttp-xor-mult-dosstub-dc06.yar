rule TTP_XOR_MULT_DOSStub_dc06 {
  strings:
    $key_dc06 = { 88 6e [2] fc 76 [2] bb 74 [2] fc 65 [2] b2 69 [2] be 63 [2] a9 68 [2] b2 26 [2] 8f }

  condition:
    any of them
}