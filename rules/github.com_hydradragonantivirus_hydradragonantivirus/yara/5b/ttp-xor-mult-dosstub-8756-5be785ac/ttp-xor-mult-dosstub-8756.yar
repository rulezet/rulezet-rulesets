rule TTP_XOR_MULT_DOSStub_8756 {
  strings:
    $key_8756 = { d3 3e [2] a7 26 [2] e0 24 [2] a7 35 [2] e9 39 [2] e5 33 [2] f2 38 [2] e9 76 [2] d4 }

  condition:
    any of them
}