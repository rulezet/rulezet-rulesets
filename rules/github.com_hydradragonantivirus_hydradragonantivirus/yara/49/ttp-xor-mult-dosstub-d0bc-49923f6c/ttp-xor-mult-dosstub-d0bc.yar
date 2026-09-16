rule TTP_XOR_MULT_DOSStub_d0bc {
  strings:
    $key_d0bc = { 84 d4 [2] f0 cc [2] b7 ce [2] f0 df [2] be d3 [2] b2 d9 [2] a5 d2 [2] be 9c [2] 83 }

  condition:
    any of them
}