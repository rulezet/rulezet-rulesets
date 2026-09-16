rule TTP_XOR_MULT_DOSStub_08bc {
  strings:
    $key_08bc = { 5c d4 [2] 28 cc [2] 6f ce [2] 28 df [2] 66 d3 [2] 6a d9 [2] 7d d2 [2] 66 9c [2] 5b }

  condition:
    any of them
}