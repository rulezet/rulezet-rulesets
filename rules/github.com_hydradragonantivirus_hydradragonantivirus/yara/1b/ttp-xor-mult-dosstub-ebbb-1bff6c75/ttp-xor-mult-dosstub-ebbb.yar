rule TTP_XOR_MULT_DOSStub_ebbb {
  strings:
    $key_ebbb = { bf d3 [2] cb cb [2] 8c c9 [2] cb d8 [2] 85 d4 [2] 89 de [2] 9e d5 [2] 85 9b [2] b8 }

  condition:
    any of them
}