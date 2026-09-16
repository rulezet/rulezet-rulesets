rule TTP_XOR_MULT_DOSStub_a8dd {
  strings:
    $key_a8dd = { fc b5 [2] 88 ad [2] cf af [2] 88 be [2] c6 b2 [2] ca b8 [2] dd b3 [2] c6 fd [2] fb }

  condition:
    any of them
}