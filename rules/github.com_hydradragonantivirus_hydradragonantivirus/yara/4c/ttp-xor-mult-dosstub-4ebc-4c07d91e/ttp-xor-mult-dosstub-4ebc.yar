rule TTP_XOR_MULT_DOSStub_4ebc {
  strings:
    $key_4ebc = { 1a d4 [2] 6e cc [2] 29 ce [2] 6e df [2] 20 d3 [2] 2c d9 [2] 3b d2 [2] 20 9c [2] 1d }

  condition:
    any of them
}