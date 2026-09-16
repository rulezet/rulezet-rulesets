rule TTP_XOR_MULT_DOSStub_a756 {
  strings:
    $key_a756 = { f3 3e [2] 87 26 [2] c0 24 [2] 87 35 [2] c9 39 [2] c5 33 [2] d2 38 [2] c9 76 [2] f4 }

  condition:
    any of them
}