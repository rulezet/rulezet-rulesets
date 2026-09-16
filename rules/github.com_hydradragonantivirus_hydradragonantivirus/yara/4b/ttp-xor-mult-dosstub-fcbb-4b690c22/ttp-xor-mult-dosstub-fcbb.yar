rule TTP_XOR_MULT_DOSStub_fcbb {
  strings:
    $key_fcbb = { a8 d3 [2] dc cb [2] 9b c9 [2] dc d8 [2] 92 d4 [2] 9e de [2] 89 d5 [2] 92 9b [2] af }

  condition:
    any of them
}