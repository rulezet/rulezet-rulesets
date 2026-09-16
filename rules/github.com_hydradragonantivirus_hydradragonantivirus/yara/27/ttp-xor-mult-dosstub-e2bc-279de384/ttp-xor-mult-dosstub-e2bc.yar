rule TTP_XOR_MULT_DOSStub_e2bc {
  strings:
    $key_e2bc = { b6 d4 [2] c2 cc [2] 85 ce [2] c2 df [2] 8c d3 [2] 80 d9 [2] 97 d2 [2] 8c 9c [2] b1 }

  condition:
    any of them
}