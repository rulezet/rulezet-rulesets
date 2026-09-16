rule TTP_XOR_MULT_DOSStub_ada1 {
  strings:
    $key_ada1 = { f9 c9 [2] 8d d1 [2] ca d3 [2] 8d c2 [2] c3 ce [2] cf c4 [2] d8 cf [2] c3 81 [2] fe }

  condition:
    any of them
}