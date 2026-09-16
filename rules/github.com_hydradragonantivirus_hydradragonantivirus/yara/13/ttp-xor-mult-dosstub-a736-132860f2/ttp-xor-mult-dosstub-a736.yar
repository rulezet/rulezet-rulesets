rule TTP_XOR_MULT_DOSStub_a736 {
  strings:
    $key_a736 = { f3 5e [2] 87 46 [2] c0 44 [2] 87 55 [2] c9 59 [2] c5 53 [2] d2 58 [2] c9 16 [2] f4 }

  condition:
    any of them
}