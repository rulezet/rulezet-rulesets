rule TTP_XOR_MULT_DOSStub_10bc {
  strings:
    $key_10bc = { 44 d4 [2] 30 cc [2] 77 ce [2] 30 df [2] 7e d3 [2] 72 d9 [2] 65 d2 [2] 7e 9c [2] 43 }

  condition:
    any of them
}