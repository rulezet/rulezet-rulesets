rule TTP_XOR_MULT_DOSStub_8718 {
  strings:
    $key_8718 = { d3 70 [2] a7 68 [2] e0 6a [2] a7 7b [2] e9 77 [2] e5 7d [2] f2 76 [2] e9 38 [2] d4 }

  condition:
    any of them
}