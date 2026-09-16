rule TTP_XOR_MULT_DOSStub_68a5 {
  strings:
    $key_68a5 = { 3c cd [2] 48 d5 [2] 0f d7 [2] 48 c6 [2] 06 ca [2] 0a c0 [2] 1d cb [2] 06 85 [2] 3b }

  condition:
    any of them
}