rule TTP_XOR_MULT_DOSStub_38bc {
  strings:
    $key_38bc = { 6c d4 [2] 18 cc [2] 5f ce [2] 18 df [2] 56 d3 [2] 5a d9 [2] 4d d2 [2] 56 9c [2] 6b }

  condition:
    any of them
}