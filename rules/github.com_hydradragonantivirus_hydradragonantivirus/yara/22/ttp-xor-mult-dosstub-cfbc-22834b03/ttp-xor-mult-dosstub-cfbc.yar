rule TTP_XOR_MULT_DOSStub_cfbc {
  strings:
    $key_cfbc = { 9b d4 [2] ef cc [2] a8 ce [2] ef df [2] a1 d3 [2] ad d9 [2] ba d2 [2] a1 9c [2] 9c }

  condition:
    any of them
}