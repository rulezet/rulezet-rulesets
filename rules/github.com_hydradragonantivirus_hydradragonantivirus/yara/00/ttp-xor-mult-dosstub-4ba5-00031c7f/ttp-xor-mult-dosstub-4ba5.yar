rule TTP_XOR_MULT_DOSStub_4ba5 {
  strings:
    $key_4ba5 = { 1f cd [2] 6b d5 [2] 2c d7 [2] 6b c6 [2] 25 ca [2] 29 c0 [2] 3e cb [2] 25 85 [2] 18 }

  condition:
    any of them
}