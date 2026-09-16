rule TTP_XOR_MULT_DOSStub_49b3 {
  strings:
    $key_49b3 = { 1d db [2] 69 c3 [2] 2e c1 [2] 69 d0 [2] 27 dc [2] 2b d6 [2] 3c dd [2] 27 93 [2] 1a }

  condition:
    any of them
}