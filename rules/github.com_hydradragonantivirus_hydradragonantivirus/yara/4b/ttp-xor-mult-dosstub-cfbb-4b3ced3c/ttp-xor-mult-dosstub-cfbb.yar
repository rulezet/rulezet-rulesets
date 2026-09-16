rule TTP_XOR_MULT_DOSStub_cfbb {
  strings:
    $key_cfbb = { 9b d3 [2] ef cb [2] a8 c9 [2] ef d8 [2] a1 d4 [2] ad de [2] ba d5 [2] a1 9b [2] 9c }

  condition:
    any of them
}