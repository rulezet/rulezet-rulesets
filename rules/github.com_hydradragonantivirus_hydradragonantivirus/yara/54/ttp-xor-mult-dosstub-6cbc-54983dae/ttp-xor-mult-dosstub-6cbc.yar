rule TTP_XOR_MULT_DOSStub_6cbc {
  strings:
    $key_6cbc = { 38 d4 [2] 4c cc [2] 0b ce [2] 4c df [2] 02 d3 [2] 0e d9 [2] 19 d2 [2] 02 9c [2] 3f }

  condition:
    any of them
}