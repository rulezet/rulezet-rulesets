rule TTP_XOR_MULT_DOSStub_0cbb {
  strings:
    $key_0cbb = { 58 d3 [2] 2c cb [2] 6b c9 [2] 2c d8 [2] 62 d4 [2] 6e de [2] 79 d5 [2] 62 9b [2] 5f }

  condition:
    any of them
}