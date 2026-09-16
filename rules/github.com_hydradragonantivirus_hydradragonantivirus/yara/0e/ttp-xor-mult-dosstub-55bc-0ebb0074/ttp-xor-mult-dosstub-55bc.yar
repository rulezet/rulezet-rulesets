rule TTP_XOR_MULT_DOSStub_55bc {
  strings:
    $key_55bc = { 01 d4 [2] 75 cc [2] 32 ce [2] 75 df [2] 3b d3 [2] 37 d9 [2] 20 d2 [2] 3b 9c [2] 06 }

  condition:
    any of them
}