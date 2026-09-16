rule TTP_XOR_MULT_DOSStub_54bc {
  strings:
    $key_54bc = { 00 d4 [2] 74 cc [2] 33 ce [2] 74 df [2] 3a d3 [2] 36 d9 [2] 21 d2 [2] 3a 9c [2] 07 }

  condition:
    any of them
}