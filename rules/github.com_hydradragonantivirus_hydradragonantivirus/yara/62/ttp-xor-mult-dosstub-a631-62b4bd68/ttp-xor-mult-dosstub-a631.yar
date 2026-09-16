rule TTP_XOR_MULT_DOSStub_a631 {
  strings:
    $key_a631 = { f2 59 [2] 86 41 [2] c1 43 [2] 86 52 [2] c8 5e [2] c4 54 [2] d3 5f [2] c8 11 [2] f5 }

  condition:
    any of them
}