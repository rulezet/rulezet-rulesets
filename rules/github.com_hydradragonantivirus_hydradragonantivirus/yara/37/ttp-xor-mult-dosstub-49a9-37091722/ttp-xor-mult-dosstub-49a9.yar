rule TTP_XOR_MULT_DOSStub_49a9 {
  strings:
    $key_49a9 = { 1d c1 [2] 69 d9 [2] 2e db [2] 69 ca [2] 27 c6 [2] 2b cc [2] 3c c7 [2] 27 89 [2] 1a }

  condition:
    any of them
}