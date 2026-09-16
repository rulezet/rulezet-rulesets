rule TTP_XOR_MULT_DOSStub_d6bc {
  strings:
    $key_d6bc = { 82 d4 [2] f6 cc [2] b1 ce [2] f6 df [2] b8 d3 [2] b4 d9 [2] a3 d2 [2] b8 9c [2] 85 }

  condition:
    any of them
}