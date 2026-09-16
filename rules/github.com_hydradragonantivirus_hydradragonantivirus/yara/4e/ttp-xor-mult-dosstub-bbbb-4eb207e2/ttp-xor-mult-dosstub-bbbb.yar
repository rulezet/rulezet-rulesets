rule TTP_XOR_MULT_DOSStub_bbbb {
  strings:
    $key_bbbb = { ef d3 [2] 9b cb [2] dc c9 [2] 9b d8 [2] d5 d4 [2] d9 de [2] ce d5 [2] d5 9b [2] e8 }

  condition:
    any of them
}