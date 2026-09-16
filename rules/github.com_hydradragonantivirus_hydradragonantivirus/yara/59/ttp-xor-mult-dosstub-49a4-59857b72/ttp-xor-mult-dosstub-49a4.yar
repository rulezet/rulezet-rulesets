rule TTP_XOR_MULT_DOSStub_49a4 {
  strings:
    $key_49a4 = { 1d cc [2] 69 d4 [2] 2e d6 [2] 69 c7 [2] 27 cb [2] 2b c1 [2] 3c ca [2] 27 84 [2] 1a }

  condition:
    any of them
}