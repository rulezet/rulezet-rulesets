rule TTP_XOR_MULT_DOSStub_a407 {
  strings:
    $key_a407 = { f0 6f [2] 84 77 [2] c3 75 [2] 84 64 [2] ca 68 [2] c6 62 [2] d1 69 [2] ca 27 [2] f7 }

  condition:
    any of them
}