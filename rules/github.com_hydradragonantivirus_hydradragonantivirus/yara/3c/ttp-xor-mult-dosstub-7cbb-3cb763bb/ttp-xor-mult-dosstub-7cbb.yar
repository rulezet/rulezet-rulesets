rule TTP_XOR_MULT_DOSStub_7cbb {
  strings:
    $key_7cbb = { 28 d3 [2] 5c cb [2] 1b c9 [2] 5c d8 [2] 12 d4 [2] 1e de [2] 09 d5 [2] 12 9b [2] 2f }

  condition:
    any of them
}