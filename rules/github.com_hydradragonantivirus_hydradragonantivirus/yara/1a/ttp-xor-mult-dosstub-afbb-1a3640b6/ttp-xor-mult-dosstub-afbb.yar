rule TTP_XOR_MULT_DOSStub_afbb {
  strings:
    $key_afbb = { fb d3 [2] 8f cb [2] c8 c9 [2] 8f d8 [2] c1 d4 [2] cd de [2] da d5 [2] c1 9b [2] fc }

  condition:
    any of them
}