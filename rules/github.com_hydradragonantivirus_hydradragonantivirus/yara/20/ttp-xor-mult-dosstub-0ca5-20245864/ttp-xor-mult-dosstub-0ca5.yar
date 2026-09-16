rule TTP_XOR_MULT_DOSStub_0ca5 {
  strings:
    $key_0ca5 = { 58 cd [2] 2c d5 [2] 6b d7 [2] 2c c6 [2] 62 ca [2] 6e c0 [2] 79 cb [2] 62 85 [2] 5f }

  condition:
    any of them
}