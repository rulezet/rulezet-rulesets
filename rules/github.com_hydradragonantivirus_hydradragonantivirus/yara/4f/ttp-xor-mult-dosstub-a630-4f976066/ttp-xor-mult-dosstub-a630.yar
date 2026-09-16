rule TTP_XOR_MULT_DOSStub_a630 {
  strings:
    $key_a630 = { f2 58 [2] 86 40 [2] c1 42 [2] 86 53 [2] c8 5f [2] c4 55 [2] d3 5e [2] c8 10 [2] f5 }

  condition:
    any of them
}