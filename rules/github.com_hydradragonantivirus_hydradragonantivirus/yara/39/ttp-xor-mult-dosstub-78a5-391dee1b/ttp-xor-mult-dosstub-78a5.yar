rule TTP_XOR_MULT_DOSStub_78a5 {
  strings:
    $key_78a5 = { 2c cd [2] 58 d5 [2] 1f d7 [2] 58 c6 [2] 16 ca [2] 1a c0 [2] 0d cb [2] 16 85 [2] 2b }

  condition:
    any of them
}