rule TTP_XOR_MULT_DOSStub_f9a3 {
  strings:
    $key_f9a3 = { ad cb [2] d9 d3 [2] 9e d1 [2] d9 c0 [2] 97 cc [2] 9b c6 [2] 8c cd [2] 97 83 [2] aa }

  condition:
    any of them
}