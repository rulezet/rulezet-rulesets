rule TTP_XOR_MULT_DOSStub_98b0 {
  strings:
    $key_98b0 = { cc d8 [2] b8 c0 [2] ff c2 [2] b8 d3 [2] f6 df [2] fa d5 [2] ed de [2] f6 90 [2] cb }

  condition:
    any of them
}