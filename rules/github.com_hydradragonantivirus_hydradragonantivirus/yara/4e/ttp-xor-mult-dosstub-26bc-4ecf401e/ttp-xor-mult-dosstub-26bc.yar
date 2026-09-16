rule TTP_XOR_MULT_DOSStub_26bc {
  strings:
    $key_26bc = { 72 d4 [2] 06 cc [2] 41 ce [2] 06 df [2] 48 d3 [2] 44 d9 [2] 53 d2 [2] 48 9c [2] 75 }

  condition:
    any of them
}