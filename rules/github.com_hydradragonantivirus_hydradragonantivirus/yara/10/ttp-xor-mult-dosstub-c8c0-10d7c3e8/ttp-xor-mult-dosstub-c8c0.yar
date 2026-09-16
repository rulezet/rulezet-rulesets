rule TTP_XOR_MULT_DOSStub_c8c0 {
  strings:
    $key_c8c0 = { 9c a8 [2] e8 b0 [2] af b2 [2] e8 a3 [2] a6 af [2] aa a5 [2] bd ae [2] a6 e0 [2] 9b }

  condition:
    any of them
}