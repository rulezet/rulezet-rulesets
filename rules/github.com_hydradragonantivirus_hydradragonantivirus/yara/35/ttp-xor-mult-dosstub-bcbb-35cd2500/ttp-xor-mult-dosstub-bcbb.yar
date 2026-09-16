rule TTP_XOR_MULT_DOSStub_bcbb {
  strings:
    $key_bcbb = { e8 d3 [2] 9c cb [2] db c9 [2] 9c d8 [2] d2 d4 [2] de de [2] c9 d5 [2] d2 9b [2] ef }

  condition:
    any of them
}