rule TTP_XOR_MULT_DOSStub_01bc {
  strings:
    $key_01bc = { 55 d4 [2] 21 cc [2] 66 ce [2] 21 df [2] 6f d3 [2] 63 d9 [2] 74 d2 [2] 6f 9c [2] 52 }

  condition:
    any of them
}