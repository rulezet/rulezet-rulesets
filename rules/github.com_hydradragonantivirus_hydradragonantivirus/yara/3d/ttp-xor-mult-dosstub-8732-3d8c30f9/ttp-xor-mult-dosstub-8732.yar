rule TTP_XOR_MULT_DOSStub_8732 {
  strings:
    $key_8732 = { d3 5a [2] a7 42 [2] e0 40 [2] a7 51 [2] e9 5d [2] e5 57 [2] f2 5c [2] e9 12 [2] d4 }

  condition:
    any of them
}