rule TTP_XOR_MULT_DOSStub_a8d6 {
  strings:
    $key_a8d6 = { fc be [2] 88 a6 [2] cf a4 [2] 88 b5 [2] c6 b9 [2] ca b3 [2] dd b8 [2] c6 f6 [2] fb }

  condition:
    any of them
}