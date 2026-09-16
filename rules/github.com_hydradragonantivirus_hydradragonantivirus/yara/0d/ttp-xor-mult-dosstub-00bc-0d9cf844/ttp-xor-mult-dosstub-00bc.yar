rule TTP_XOR_MULT_DOSStub_00bc {
  strings:
    $key_00bc = { 54 d4 [2] 20 cc [2] 67 ce [2] 20 df [2] 6e d3 [2] 62 d9 [2] 75 d2 [2] 6e 9c [2] 53 }

  condition:
    any of them
}