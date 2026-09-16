rule TTP_XOR_MULT_DOSStub_79a3 {
  strings:
    $key_79a3 = { 2d cb [2] 59 d3 [2] 1e d1 [2] 59 c0 [2] 17 cc [2] 1b c6 [2] 0c cd [2] 17 83 [2] 2a }

  condition:
    any of them
}