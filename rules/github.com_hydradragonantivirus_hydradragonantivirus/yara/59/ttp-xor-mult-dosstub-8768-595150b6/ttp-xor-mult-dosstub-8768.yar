rule TTP_XOR_MULT_DOSStub_8768 {
  strings:
    $key_8768 = { d3 00 [2] a7 18 [2] e0 1a [2] a7 0b [2] e9 07 [2] e5 0d [2] f2 06 [2] e9 48 [2] d4 }

  condition:
    any of them
}