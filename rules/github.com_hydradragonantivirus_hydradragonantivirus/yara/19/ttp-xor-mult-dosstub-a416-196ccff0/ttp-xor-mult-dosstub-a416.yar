rule TTP_XOR_MULT_DOSStub_a416 {
  strings:
    $key_a416 = { f0 7e [2] 84 66 [2] c3 64 [2] 84 75 [2] ca 79 [2] c6 73 [2] d1 78 [2] ca 36 [2] f7 }

  condition:
    any of them
}