rule TTP_XOR_MULT_DOSStub_44bc {
  strings:
    $key_44bc = { 10 d4 [2] 64 cc [2] 23 ce [2] 64 df [2] 2a d3 [2] 26 d9 [2] 31 d2 [2] 2a 9c [2] 17 }

  condition:
    any of them
}