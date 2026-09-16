rule TTP_XOR_MULT_DOSStub_ada9 {
  strings:
    $key_ada9 = { f9 c1 [2] 8d d9 [2] ca db [2] 8d ca [2] c3 c6 [2] cf cc [2] d8 c7 [2] c3 89 [2] fe }

  condition:
    any of them
}