rule TTP_XOR_MULT_DOSStub_8746 {
  strings:
    $key_8746 = { d3 2e [2] a7 36 [2] e0 34 [2] a7 25 [2] e9 29 [2] e5 23 [2] f2 28 [2] e9 66 [2] d4 }

  condition:
    any of them
}