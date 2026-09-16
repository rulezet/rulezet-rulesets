rule TTP_XOR_MULT_DOSStub_2ebc {
  strings:
    $key_2ebc = { 7a d4 [2] 0e cc [2] 49 ce [2] 0e df [2] 40 d3 [2] 4c d9 [2] 5b d2 [2] 40 9c [2] 7d }

  condition:
    any of them
}