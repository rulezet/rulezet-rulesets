rule TTP_XOR_MULT_DOSStub_5cbc {
  strings:
    $key_5cbc = { 08 d4 [2] 7c cc [2] 3b ce [2] 7c df [2] 32 d3 [2] 3e d9 [2] 29 d2 [2] 32 9c [2] 0f }

  condition:
    any of them
}