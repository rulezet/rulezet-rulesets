rule TTP_XOR_MULT_DOSStub_20bc {
  strings:
    $key_20bc = { 74 d4 [2] 00 cc [2] 47 ce [2] 00 df [2] 4e d3 [2] 42 d9 [2] 55 d2 [2] 4e 9c [2] 73 }

  condition:
    any of them
}