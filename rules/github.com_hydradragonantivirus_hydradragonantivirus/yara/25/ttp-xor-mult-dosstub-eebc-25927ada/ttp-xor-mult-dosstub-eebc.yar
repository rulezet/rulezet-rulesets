rule TTP_XOR_MULT_DOSStub_eebc {
  strings:
    $key_eebc = { ba d4 [2] ce cc [2] 89 ce [2] ce df [2] 80 d3 [2] 8c d9 [2] 9b d2 [2] 80 9c [2] bd }

  condition:
    any of them
}