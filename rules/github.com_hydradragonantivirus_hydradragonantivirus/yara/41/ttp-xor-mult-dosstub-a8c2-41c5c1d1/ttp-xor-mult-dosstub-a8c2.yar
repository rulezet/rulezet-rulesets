rule TTP_XOR_MULT_DOSStub_a8c2 {
  strings:
    $key_a8c2 = { fc aa [2] 88 b2 [2] cf b0 [2] 88 a1 [2] c6 ad [2] ca a7 [2] dd ac [2] c6 e2 [2] fb }

  condition:
    any of them
}