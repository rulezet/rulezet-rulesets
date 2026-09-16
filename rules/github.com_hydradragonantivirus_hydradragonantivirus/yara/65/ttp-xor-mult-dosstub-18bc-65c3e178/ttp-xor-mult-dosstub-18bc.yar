rule TTP_XOR_MULT_DOSStub_18bc {
  strings:
    $key_18bc = { 4c d4 [2] 38 cc [2] 7f ce [2] 38 df [2] 76 d3 [2] 7a d9 [2] 6d d2 [2] 76 9c [2] 4b }

  condition:
    any of them
}