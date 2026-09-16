rule TTP_XOR_MULT_DOSStub_8706 {
  strings:
    $key_8706 = { d3 6e [2] a7 76 [2] e0 74 [2] a7 65 [2] e9 69 [2] e5 63 [2] f2 68 [2] e9 26 [2] d4 }

  condition:
    any of them
}