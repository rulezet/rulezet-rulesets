rule TTP_XOR_MULT_DOSStub_ddbb {
  strings:
    $key_ddbb = { 89 d3 [2] fd cb [2] ba c9 [2] fd d8 [2] b3 d4 [2] bf de [2] a8 d5 [2] b3 9b [2] 8e }

  condition:
    any of them
}