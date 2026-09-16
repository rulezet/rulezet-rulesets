rule TTP_XOR_MULT_DOSStub_a660 {
  strings:
    $key_a660 = { f2 08 [2] 86 10 [2] c1 12 [2] 86 03 [2] c8 0f [2] c4 05 [2] d3 0e [2] c8 40 [2] f5 }

  condition:
    any of them
}