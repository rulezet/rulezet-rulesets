rule TTP_XOR_MULT_DOSStub_a401 {
  strings:
    $key_a401 = { f0 69 [2] 84 71 [2] c3 73 [2] 84 62 [2] ca 6e [2] c6 64 [2] d1 6f [2] ca 21 [2] f7 }

  condition:
    any of them
}