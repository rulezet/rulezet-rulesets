rule TTP_XOR_MULT_DOSStub_50bc {
  strings:
    $key_50bc = { 04 d4 [2] 70 cc [2] 37 ce [2] 70 df [2] 3e d3 [2] 32 d9 [2] 25 d2 [2] 3e 9c [2] 03 }

  condition:
    any of them
}