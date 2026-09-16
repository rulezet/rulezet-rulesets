rule TTP_XOR_MULT_DOSStub_7ebc {
  strings:
    $key_7ebc = { 2a d4 [2] 5e cc [2] 19 ce [2] 5e df [2] 10 d3 [2] 1c d9 [2] 0b d2 [2] 10 9c [2] 2d }

  condition:
    any of them
}