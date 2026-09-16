rule TTP_XOR_MULT_DOSStub_a6cb {
  strings:
    $key_a6cb = { f2 a3 [2] 86 bb [2] c1 b9 [2] 86 a8 [2] c8 a4 [2] c4 ae [2] d3 a5 [2] c8 eb [2] f5 }

  condition:
    any of them
}