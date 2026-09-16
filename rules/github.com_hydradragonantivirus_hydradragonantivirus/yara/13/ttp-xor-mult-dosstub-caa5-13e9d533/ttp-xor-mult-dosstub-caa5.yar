rule TTP_XOR_MULT_DOSStub_caa5 {
  strings:
    $key_caa5 = { 9e cd [2] ea d5 [2] ad d7 [2] ea c6 [2] a4 ca [2] a8 c0 [2] bf cb [2] a4 85 [2] 99 }

  condition:
    any of them
}