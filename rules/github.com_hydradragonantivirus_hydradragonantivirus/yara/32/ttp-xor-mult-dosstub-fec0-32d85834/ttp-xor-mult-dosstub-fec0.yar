rule TTP_XOR_MULT_DOSStub_fec0 {
  strings:
    $key_fec0 = { aa a8 [2] de b0 [2] 99 b2 [2] de a3 [2] 90 af [2] 9c a5 [2] 8b ae [2] 90 e0 [2] ad }

  condition:
    any of them
}