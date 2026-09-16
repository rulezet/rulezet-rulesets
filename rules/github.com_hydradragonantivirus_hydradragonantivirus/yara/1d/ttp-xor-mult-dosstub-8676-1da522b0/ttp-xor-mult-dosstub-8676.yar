rule TTP_XOR_MULT_DOSStub_8676 {
  strings:
    $key_8676 = { d2 1e [2] a6 06 [2] e1 04 [2] a6 15 [2] e8 19 [2] e4 13 [2] f3 18 [2] e8 56 [2] d5 }

  condition:
    any of them
}