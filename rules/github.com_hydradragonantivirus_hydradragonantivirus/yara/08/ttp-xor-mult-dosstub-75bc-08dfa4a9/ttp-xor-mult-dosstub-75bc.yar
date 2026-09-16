rule TTP_XOR_MULT_DOSStub_75bc {
  strings:
    $key_75bc = { 21 d4 [2] 55 cc [2] 12 ce [2] 55 df [2] 1b d3 [2] 17 d9 [2] 00 d2 [2] 1b 9c [2] 26 }

  condition:
    any of them
}