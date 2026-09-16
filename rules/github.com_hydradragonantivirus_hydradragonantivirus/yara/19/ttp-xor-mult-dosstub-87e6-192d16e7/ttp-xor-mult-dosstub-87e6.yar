rule TTP_XOR_MULT_DOSStub_87e6 {
  strings:
    $key_87e6 = { d3 8e [2] a7 96 [2] e0 94 [2] a7 85 [2] e9 89 [2] e5 83 [2] f2 88 [2] e9 c6 [2] d4 }

  condition:
    any of them
}