rule TTP_XOR_MULT_DOSStub_c8a5 {
  strings:
    $key_c8a5 = { 9c cd [2] e8 d5 [2] af d7 [2] e8 c6 [2] a6 ca [2] aa c0 [2] bd cb [2] a6 85 [2] 9b }

  condition:
    any of them
}