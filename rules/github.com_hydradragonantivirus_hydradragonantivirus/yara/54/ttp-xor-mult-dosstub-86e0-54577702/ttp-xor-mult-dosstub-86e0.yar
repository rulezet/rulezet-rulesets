rule TTP_XOR_MULT_DOSStub_86e0 {
  strings:
    $key_86e0 = { d2 88 [2] a6 90 [2] e1 92 [2] a6 83 [2] e8 8f [2] e4 85 [2] f3 8e [2] e8 c0 [2] d5 }

  condition:
    any of them
}