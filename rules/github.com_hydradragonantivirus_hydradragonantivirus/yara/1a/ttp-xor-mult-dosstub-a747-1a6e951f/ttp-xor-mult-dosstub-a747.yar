rule TTP_XOR_MULT_DOSStub_a747 {
  strings:
    $key_a747 = { f3 2f [2] 87 37 [2] c0 35 [2] 87 24 [2] c9 28 [2] c5 22 [2] d2 29 [2] c9 67 [2] f4 }

  condition:
    any of them
}