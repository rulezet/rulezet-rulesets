rule TTP_XOR_MULT_DOSStub_a670 {
  strings:
    $key_a670 = { f2 18 [2] 86 00 [2] c1 02 [2] 86 13 [2] c8 1f [2] c4 15 [2] d3 1e [2] c8 50 [2] f5 }

  condition:
    any of them
}