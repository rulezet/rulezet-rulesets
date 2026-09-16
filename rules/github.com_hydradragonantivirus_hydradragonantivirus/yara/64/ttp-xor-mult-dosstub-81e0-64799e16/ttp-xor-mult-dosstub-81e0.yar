rule TTP_XOR_MULT_DOSStub_81e0 {
  strings:
    $key_81e0 = { d5 88 [2] a1 90 [2] e6 92 [2] a1 83 [2] ef 8f [2] e3 85 [2] f4 8e [2] ef c0 [2] d2 }

  condition:
    any of them
}