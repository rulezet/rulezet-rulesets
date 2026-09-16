rule TTP_XOR_MULT_DOSStub_e6bc {
  strings:
    $key_e6bc = { b2 d4 [2] c6 cc [2] 81 ce [2] c6 df [2] 88 d3 [2] 84 d9 [2] 93 d2 [2] 88 9c [2] b5 }

  condition:
    any of them
}