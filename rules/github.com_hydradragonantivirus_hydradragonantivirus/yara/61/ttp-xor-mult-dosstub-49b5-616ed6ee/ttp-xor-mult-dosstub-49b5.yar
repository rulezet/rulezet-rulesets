rule TTP_XOR_MULT_DOSStub_49b5 {
  strings:
    $key_49b5 = { 1d dd [2] 69 c5 [2] 2e c7 [2] 69 d6 [2] 27 da [2] 2b d0 [2] 3c db [2] 27 95 [2] 1a }

  condition:
    any of them
}