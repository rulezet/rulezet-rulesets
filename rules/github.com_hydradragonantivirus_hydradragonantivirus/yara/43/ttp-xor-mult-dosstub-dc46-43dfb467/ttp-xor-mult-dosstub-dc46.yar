rule TTP_XOR_MULT_DOSStub_dc46 {
  strings:
    $key_dc46 = { 88 2e [2] fc 36 [2] bb 34 [2] fc 25 [2] b2 29 [2] be 23 [2] a9 28 [2] b2 66 [2] 8f }

  condition:
    any of them
}