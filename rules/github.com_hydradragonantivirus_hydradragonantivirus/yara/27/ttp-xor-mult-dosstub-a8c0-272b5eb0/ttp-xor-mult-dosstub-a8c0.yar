rule TTP_XOR_MULT_DOSStub_a8c0 {
  strings:
    $key_a8c0 = { fc a8 [2] 88 b0 [2] cf b2 [2] 88 a3 [2] c6 af [2] ca a5 [2] dd ae [2] c6 e0 [2] fb }

  condition:
    any of them
}