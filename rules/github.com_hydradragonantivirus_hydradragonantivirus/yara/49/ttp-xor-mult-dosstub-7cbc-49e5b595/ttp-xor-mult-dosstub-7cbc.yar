rule TTP_XOR_MULT_DOSStub_7cbc {
  strings:
    $key_7cbc = { 28 d4 [2] 5c cc [2] 1b ce [2] 5c df [2] 12 d3 [2] 1e d9 [2] 09 d2 [2] 12 9c [2] 2f }

  condition:
    any of them
}