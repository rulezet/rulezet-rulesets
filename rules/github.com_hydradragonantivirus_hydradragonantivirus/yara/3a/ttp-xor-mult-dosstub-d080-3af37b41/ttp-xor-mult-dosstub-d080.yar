rule TTP_XOR_MULT_DOSStub_d080 {
  strings:
    $key_d080 = { 84 e8 [2] f0 f0 [2] b7 f2 [2] f0 e3 [2] be ef [2] b2 e5 [2] a5 ee [2] be a0 [2] 83 }

  condition:
    any of them
}