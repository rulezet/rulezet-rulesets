rule TTP_XOR_MULT_DOSStub_a677 {
  strings:
    $key_a677 = { f2 1f [2] 86 07 [2] c1 05 [2] 86 14 [2] c8 18 [2] c4 12 [2] d3 19 [2] c8 57 [2] f5 }

  condition:
    any of them
}