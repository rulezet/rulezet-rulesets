rule TTP_XOR_MULT_DOSStub_77bc {
  strings:
    $key_77bc = { 23 d4 [2] 57 cc [2] 10 ce [2] 57 df [2] 19 d3 [2] 15 d9 [2] 02 d2 [2] 19 9c [2] 24 }

  condition:
    any of them
}