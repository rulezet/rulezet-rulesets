rule TTP_XOR_MULT_DOSStub_dcbc {
  strings:
    $key_dcbc = { 88 d4 [2] fc cc [2] bb ce [2] fc df [2] b2 d3 [2] be d9 [2] a9 d2 [2] b2 9c [2] 8f }

  condition:
    any of them
}