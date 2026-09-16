rule TTP_XOR_MULT_DOSStub_8747 {
  strings:
    $key_8747 = { d3 2f [2] a7 37 [2] e0 35 [2] a7 24 [2] e9 28 [2] e5 22 [2] f2 29 [2] e9 67 [2] d4 }

  condition:
    any of them
}