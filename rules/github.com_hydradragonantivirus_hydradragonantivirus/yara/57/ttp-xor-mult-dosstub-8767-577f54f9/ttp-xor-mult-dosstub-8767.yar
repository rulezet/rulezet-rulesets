rule TTP_XOR_MULT_DOSStub_8767 {
  strings:
    $key_8767 = { d3 0f [2] a7 17 [2] e0 15 [2] a7 04 [2] e9 08 [2] e5 02 [2] f2 09 [2] e9 47 [2] d4 }

  condition:
    any of them
}