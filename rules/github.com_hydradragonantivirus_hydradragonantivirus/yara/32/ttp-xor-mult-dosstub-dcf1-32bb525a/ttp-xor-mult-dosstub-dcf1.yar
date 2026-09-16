rule TTP_XOR_MULT_DOSStub_dcf1 {
  strings:
    $key_dcf1 = { 88 99 [2] fc 81 [2] bb 83 [2] fc 92 [2] b2 9e [2] be 94 [2] a9 9f [2] b2 d1 [2] 8f }

  condition:
    any of them
}