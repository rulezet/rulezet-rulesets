rule TTP_XOR_MULT_DOSStub_49a3 {
  strings:
    $key_49a3 = { 1d cb [2] 69 d3 [2] 2e d1 [2] 69 c0 [2] 27 cc [2] 2b c6 [2] 3c cd [2] 27 83 [2] 1a }

  condition:
    any of them
}