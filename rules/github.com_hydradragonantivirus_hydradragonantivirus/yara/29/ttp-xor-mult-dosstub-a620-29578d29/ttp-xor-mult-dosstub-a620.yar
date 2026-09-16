rule TTP_XOR_MULT_DOSStub_a620 {
  strings:
    $key_a620 = { f2 48 [2] 86 50 [2] c1 52 [2] 86 43 [2] c8 4f [2] c4 45 [2] d3 4e [2] c8 00 [2] f5 }

  condition:
    any of them
}