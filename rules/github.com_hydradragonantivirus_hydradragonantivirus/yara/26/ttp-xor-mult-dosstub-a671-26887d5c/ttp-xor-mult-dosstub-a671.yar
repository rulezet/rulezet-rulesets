rule TTP_XOR_MULT_DOSStub_a671 {
  strings:
    $key_a671 = { f2 19 [2] 86 01 [2] c1 03 [2] 86 12 [2] c8 1e [2] c4 14 [2] d3 1f [2] c8 51 [2] f5 }

  condition:
    any of them
}