rule TTP_XOR_MULT_DOSStub_a446 {
  strings:
    $key_a446 = { f0 2e [2] 84 36 [2] c3 34 [2] 84 25 [2] ca 29 [2] c6 23 [2] d1 28 [2] ca 66 [2] f7 }

  condition:
    any of them
}