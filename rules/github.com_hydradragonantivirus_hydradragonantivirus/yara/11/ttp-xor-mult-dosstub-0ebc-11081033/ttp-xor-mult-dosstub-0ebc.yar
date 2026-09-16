rule TTP_XOR_MULT_DOSStub_0ebc {
  strings:
    $key_0ebc = { 5a d4 [2] 2e cc [2] 69 ce [2] 2e df [2] 60 d3 [2] 6c d9 [2] 7b d2 [2] 60 9c [2] 5d }

  condition:
    any of them
}