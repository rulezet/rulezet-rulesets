rule TTP_XOR_MULT_DOSStub_a410 {
  strings:
    $key_a410 = { f0 78 [2] 84 60 [2] c3 62 [2] 84 73 [2] ca 7f [2] c6 75 [2] d1 7e [2] ca 30 [2] f7 }

  condition:
    any of them
}