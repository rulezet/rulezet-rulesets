rule TTP_XOR_MULT_DOSStub_5cbb {
  strings:
    $key_5cbb = { 08 d3 [2] 7c cb [2] 3b c9 [2] 7c d8 [2] 32 d4 [2] 3e de [2] 29 d5 [2] 32 9b [2] 0f }

  condition:
    any of them
}