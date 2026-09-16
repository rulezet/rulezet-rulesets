rule TTP_XOR_MULT_DOSStub_a437 {
  strings:
    $key_a437 = { f0 5f [2] 84 47 [2] c3 45 [2] 84 54 [2] ca 58 [2] c6 52 [2] d1 59 [2] ca 17 [2] f7 }

  condition:
    any of them
}