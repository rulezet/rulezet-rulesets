rule TTP_XOR_MULT_DOSStub_62bc {
  strings:
    $key_62bc = { 36 d4 [2] 42 cc [2] 05 ce [2] 42 df [2] 0c d3 [2] 00 d9 [2] 17 d2 [2] 0c 9c [2] 31 }

  condition:
    any of them
}