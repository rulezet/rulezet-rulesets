rule TTP_XOR_MULT_DOSStub_d9b0 {
  strings:
    $key_d9b0 = { 8d d8 [2] f9 c0 [2] be c2 [2] f9 d3 [2] b7 df [2] bb d5 [2] ac de [2] b7 90 [2] 8a }

  condition:
    any of them
}