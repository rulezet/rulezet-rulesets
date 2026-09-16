rule TTP_XOR_MULT_DOSStub_a730 {
  strings:
    $key_a730 = { f3 58 [2] 87 40 [2] c0 42 [2] 87 53 [2] c9 5f [2] c5 55 [2] d2 5e [2] c9 10 [2] f4 }

  condition:
    any of them
}