rule TTP_XOR_MULT_DOSStub_a8d1 {
  strings:
    $key_a8d1 = { fc b9 [2] 88 a1 [2] cf a3 [2] 88 b2 [2] c6 be [2] ca b4 [2] dd bf [2] c6 f1 [2] fb }

  condition:
    any of them
}