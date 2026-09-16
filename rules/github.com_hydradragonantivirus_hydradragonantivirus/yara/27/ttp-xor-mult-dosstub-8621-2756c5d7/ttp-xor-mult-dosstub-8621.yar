rule TTP_XOR_MULT_DOSStub_8621 {
  strings:
    $key_8621 = { d2 49 [2] a6 51 [2] e1 53 [2] a6 42 [2] e8 4e [2] e4 44 [2] f3 4f [2] e8 01 [2] d5 }

  condition:
    any of them
}