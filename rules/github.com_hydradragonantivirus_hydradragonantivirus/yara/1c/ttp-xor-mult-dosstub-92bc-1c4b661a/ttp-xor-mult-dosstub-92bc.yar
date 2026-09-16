rule TTP_XOR_MULT_DOSStub_92bc {
  strings:
    $key_92bc = { c6 d4 [2] b2 cc [2] f5 ce [2] b2 df [2] fc d3 [2] f0 d9 [2] e7 d2 [2] fc 9c [2] c1 }

  condition:
    any of them
}