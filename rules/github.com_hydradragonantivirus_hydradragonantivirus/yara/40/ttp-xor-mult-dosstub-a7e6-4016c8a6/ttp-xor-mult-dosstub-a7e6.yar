rule TTP_XOR_MULT_DOSStub_a7e6 {
  strings:
    $key_a7e6 = { f3 8e [2] 87 96 [2] c0 94 [2] 87 85 [2] c9 89 [2] c5 83 [2] d2 88 [2] c9 c6 [2] f4 }

  condition:
    any of them
}