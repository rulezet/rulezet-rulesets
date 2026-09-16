rule TTP_XOR_MULT_DOSStub_8707 {
  strings:
    $key_8707 = { d3 6f [2] a7 77 [2] e0 75 [2] a7 64 [2] e9 68 [2] e5 62 [2] f2 69 [2] e9 27 [2] d4 }

  condition:
    any of them
}