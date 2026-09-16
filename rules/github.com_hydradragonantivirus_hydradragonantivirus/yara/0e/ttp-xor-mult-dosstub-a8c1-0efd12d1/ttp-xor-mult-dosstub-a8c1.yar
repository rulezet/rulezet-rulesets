rule TTP_XOR_MULT_DOSStub_a8c1 {
  strings:
    $key_a8c1 = { fc a9 [2] 88 b1 [2] cf b3 [2] 88 a2 [2] c6 ae [2] ca a4 [2] dd af [2] c6 e1 [2] fb }

  condition:
    any of them
}