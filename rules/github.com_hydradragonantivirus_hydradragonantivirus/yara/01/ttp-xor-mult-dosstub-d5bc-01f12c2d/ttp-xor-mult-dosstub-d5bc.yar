rule TTP_XOR_MULT_DOSStub_d5bc {
  strings:
    $key_d5bc = { 81 d4 [2] f5 cc [2] b2 ce [2] f5 df [2] bb d3 [2] b7 d9 [2] a0 d2 [2] bb 9c [2] 86 }

  condition:
    any of them
}