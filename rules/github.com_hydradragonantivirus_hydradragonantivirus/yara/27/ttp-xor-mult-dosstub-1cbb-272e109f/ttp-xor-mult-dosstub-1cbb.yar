rule TTP_XOR_MULT_DOSStub_1cbb {
  strings:
    $key_1cbb = { 48 d3 [2] 3c cb [2] 7b c9 [2] 3c d8 [2] 72 d4 [2] 7e de [2] 69 d5 [2] 72 9b [2] 4f }

  condition:
    any of them
}