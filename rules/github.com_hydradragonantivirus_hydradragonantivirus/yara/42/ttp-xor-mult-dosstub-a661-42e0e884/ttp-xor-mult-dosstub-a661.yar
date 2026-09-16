rule TTP_XOR_MULT_DOSStub_a661 {
  strings:
    $key_a661 = { f2 09 [2] 86 11 [2] c1 13 [2] 86 02 [2] c8 0e [2] c4 04 [2] d3 0f [2] c8 41 [2] f5 }

  condition:
    any of them
}