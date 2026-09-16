rule TTP_XOR_MULT_DOSStub_a45b {
  strings:
    $key_a45b = { f0 33 [2] 84 2b [2] c3 29 [2] 84 38 [2] ca 34 [2] c6 3e [2] d1 35 [2] ca 7b [2] f7 }

  condition:
    any of them
}