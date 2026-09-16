rule TTP_XOR_MULT_DOSStub_8745 {
  strings:
    $key_8745 = { d3 2d [2] a7 35 [2] e0 37 [2] a7 26 [2] e9 2a [2] e5 20 [2] f2 2b [2] e9 65 [2] d4 }

  condition:
    any of them
}