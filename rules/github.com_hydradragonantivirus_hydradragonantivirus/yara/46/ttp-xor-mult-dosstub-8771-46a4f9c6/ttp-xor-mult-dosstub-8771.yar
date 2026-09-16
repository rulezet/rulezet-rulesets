rule TTP_XOR_MULT_DOSStub_8771 {
  strings:
    $key_8771 = { d3 19 [2] a7 01 [2] e0 03 [2] a7 12 [2] e9 1e [2] e5 14 [2] f2 1f [2] e9 51 [2] d4 }

  condition:
    any of them
}