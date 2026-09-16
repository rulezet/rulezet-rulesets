rule TTP_XOR_MULT_DOSStub_d7bc {
  strings:
    $key_d7bc = { 83 d4 [2] f7 cc [2] b0 ce [2] f7 df [2] b9 d3 [2] b5 d9 [2] a2 d2 [2] b9 9c [2] 84 }

  condition:
    any of them
}