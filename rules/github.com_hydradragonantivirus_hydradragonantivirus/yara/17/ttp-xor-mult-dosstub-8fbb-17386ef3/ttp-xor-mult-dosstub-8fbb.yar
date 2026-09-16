rule TTP_XOR_MULT_DOSStub_8fbb {
  strings:
    $key_8fbb = { db d3 [2] af cb [2] e8 c9 [2] af d8 [2] e1 d4 [2] ed de [2] fa d5 [2] e1 9b [2] dc }

  condition:
    any of them
}