rule TTP_XOR_MULT_DOSStub_49b9 {
  strings:
    $key_49b9 = { 1d d1 [2] 69 c9 [2] 2e cb [2] 69 da [2] 27 d6 [2] 2b dc [2] 3c d7 [2] 27 99 [2] 1a }

  condition:
    any of them
}