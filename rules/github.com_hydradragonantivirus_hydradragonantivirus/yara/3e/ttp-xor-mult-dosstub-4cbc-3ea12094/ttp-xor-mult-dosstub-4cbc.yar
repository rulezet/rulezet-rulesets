rule TTP_XOR_MULT_DOSStub_4cbc {
  strings:
    $key_4cbc = { 18 d4 [2] 6c cc [2] 2b ce [2] 6c df [2] 22 d3 [2] 2e d9 [2] 39 d2 [2] 22 9c [2] 1f }

  condition:
    any of them
}