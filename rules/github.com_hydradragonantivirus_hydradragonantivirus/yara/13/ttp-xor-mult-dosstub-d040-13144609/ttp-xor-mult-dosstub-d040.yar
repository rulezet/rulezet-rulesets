rule TTP_XOR_MULT_DOSStub_d040 {
  strings:
    $key_d040 = { 84 28 [2] f0 30 [2] b7 32 [2] f0 23 [2] be 2f [2] b2 25 [2] a5 2e [2] be 60 [2] 83 }

  condition:
    any of them
}