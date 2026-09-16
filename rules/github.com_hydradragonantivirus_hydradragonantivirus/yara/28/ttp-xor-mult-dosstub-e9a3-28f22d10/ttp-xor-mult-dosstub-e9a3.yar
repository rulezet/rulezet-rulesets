rule TTP_XOR_MULT_DOSStub_e9a3 {
  strings:
    $key_e9a3 = { bd cb [2] c9 d3 [2] 8e d1 [2] c9 c0 [2] 87 cc [2] 8b c6 [2] 9c cd [2] 87 83 [2] ba }

  condition:
    any of them
}