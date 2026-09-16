rule TTP_XOR_MULT_DOSStub_ada0 {
  strings:
    $key_ada0 = { f9 c8 [2] 8d d0 [2] ca d2 [2] 8d c3 [2] c3 cf [2] cf c5 [2] d8 ce [2] c3 80 [2] fe }

  condition:
    any of them
}