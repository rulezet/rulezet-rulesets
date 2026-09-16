rule TTP_XOR_MULT_DOSStub_0ba5 {
  strings:
    $key_0ba5 = { 5f cd [2] 2b d5 [2] 6c d7 [2] 2b c6 [2] 65 ca [2] 69 c0 [2] 7e cb [2] 65 85 [2] 58 }

  condition:
    any of them
}