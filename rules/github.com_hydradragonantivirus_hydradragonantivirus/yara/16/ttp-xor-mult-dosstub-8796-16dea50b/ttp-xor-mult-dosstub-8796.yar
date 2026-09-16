rule TTP_XOR_MULT_DOSStub_8796 {
  strings:
    $key_8796 = { d3 fe [2] a7 e6 [2] e0 e4 [2] a7 f5 [2] e9 f9 [2] e5 f3 [2] f2 f8 [2] e9 b6 [2] d4 }

  condition:
    any of them
}