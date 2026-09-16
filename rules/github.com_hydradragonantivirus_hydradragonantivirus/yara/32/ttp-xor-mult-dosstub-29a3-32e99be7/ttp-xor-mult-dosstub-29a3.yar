rule TTP_XOR_MULT_DOSStub_29a3 {
  strings:
    $key_29a3 = { 7d cb [2] 09 d3 [2] 4e d1 [2] 09 c0 [2] 47 cc [2] 4b c6 [2] 5c cd [2] 47 83 [2] 7a }

  condition:
    any of them
}