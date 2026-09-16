rule TTP_XOR_MULT_DOSStub_39a3 {
  strings:
    $key_39a3 = { 6d cb [2] 19 d3 [2] 5e d1 [2] 19 c0 [2] 57 cc [2] 5b c6 [2] 4c cd [2] 57 83 [2] 6a }

  condition:
    any of them
}