rule TTP_XOR_MULT_DOSStub_79a5 {
  strings:
    $key_79a5 = { 2d cd [2] 59 d5 [2] 1e d7 [2] 59 c6 [2] 17 ca [2] 1b c0 [2] 0c cb [2] 17 85 [2] 2a }

  condition:
    any of them
}