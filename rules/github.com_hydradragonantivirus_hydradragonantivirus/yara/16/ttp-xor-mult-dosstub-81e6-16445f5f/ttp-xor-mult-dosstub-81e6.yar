rule TTP_XOR_MULT_DOSStub_81e6 {
  strings:
    $key_81e6 = { d5 8e [2] a1 96 [2] e6 94 [2] a1 85 [2] ef 89 [2] e3 83 [2] f4 88 [2] ef c6 [2] d2 }

  condition:
    any of them
}