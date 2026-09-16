rule TTP_XOR_MULT_DOSStub_28a5 {
  strings:
    $key_28a5 = { 7c cd [2] 08 d5 [2] 4f d7 [2] 08 c6 [2] 46 ca [2] 4a c0 [2] 5d cb [2] 46 85 [2] 7b }

  condition:
    any of them
}