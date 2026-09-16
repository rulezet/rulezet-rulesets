rule TTP_XOR_MULT_DOSStub_39bc {
  strings:
    $key_39bc = { 6d d4 [2] 19 cc [2] 5e ce [2] 19 df [2] 57 d3 [2] 5b d9 [2] 4c d2 [2] 57 9c [2] 6a }

  condition:
    any of them
}