rule TTP_XOR_MULT_DOSStub_67bc {
  strings:
    $key_67bc = { 33 d4 [2] 47 cc [2] 00 ce [2] 47 df [2] 09 d3 [2] 05 d9 [2] 12 d2 [2] 09 9c [2] 34 }

  condition:
    any of them
}