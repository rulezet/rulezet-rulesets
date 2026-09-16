rule TTP_XOR_MULT_DOSStub_8766 {
  strings:
    $key_8766 = { d3 0e [2] a7 16 [2] e0 14 [2] a7 05 [2] e9 09 [2] e5 03 [2] f2 08 [2] e9 46 [2] d4 }

  condition:
    any of them
}