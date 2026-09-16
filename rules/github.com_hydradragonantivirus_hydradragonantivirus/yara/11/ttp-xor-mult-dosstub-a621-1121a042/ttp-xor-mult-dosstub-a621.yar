rule TTP_XOR_MULT_DOSStub_a621 {
  strings:
    $key_a621 = { f2 49 [2] 86 51 [2] c1 53 [2] 86 42 [2] c8 4e [2] c4 44 [2] d3 4f [2] c8 01 [2] f5 }

  condition:
    any of them
}