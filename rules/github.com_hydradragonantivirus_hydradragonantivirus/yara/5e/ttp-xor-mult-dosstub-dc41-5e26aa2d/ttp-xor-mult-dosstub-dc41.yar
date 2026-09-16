rule TTP_XOR_MULT_DOSStub_dc41 {
  strings:
    $key_dc41 = { 88 29 [2] fc 31 [2] bb 33 [2] fc 22 [2] b2 2e [2] be 24 [2] a9 2f [2] b2 61 [2] 8f }

  condition:
    any of them
}