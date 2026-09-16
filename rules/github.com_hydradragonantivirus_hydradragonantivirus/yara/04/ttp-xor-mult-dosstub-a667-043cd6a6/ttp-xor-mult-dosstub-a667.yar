rule TTP_XOR_MULT_DOSStub_a667 {
  strings:
    $key_a667 = { f2 0f [2] 86 17 [2] c1 15 [2] 86 04 [2] c8 08 [2] c4 02 [2] d3 09 [2] c8 47 [2] f5 }

  condition:
    any of them
}