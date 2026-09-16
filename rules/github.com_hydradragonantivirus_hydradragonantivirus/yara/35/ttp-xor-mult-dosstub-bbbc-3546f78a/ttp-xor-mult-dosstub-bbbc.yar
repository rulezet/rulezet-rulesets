rule TTP_XOR_MULT_DOSStub_bbbc {
  strings:
    $key_bbbc = { ef d4 [2] 9b cc [2] dc ce [2] 9b df [2] d5 d3 [2] d9 d9 [2] ce d2 [2] d5 9c [2] e8 }

  condition:
    any of them
}