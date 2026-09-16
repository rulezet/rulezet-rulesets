rule TTP_XOR_MULT_DOSStub_53bc {
  strings:
    $key_53bc = { 07 d4 [2] 73 cc [2] 34 ce [2] 73 df [2] 3d d3 [2] 31 d9 [2] 26 d2 [2] 3d 9c [2] 00 }

  condition:
    any of them
}