rule TTP_XOR_MULT_DOSStub_d070 {
  strings:
    $key_d070 = { 84 18 [2] f0 00 [2] b7 02 [2] f0 13 [2] be 1f [2] b2 15 [2] a5 1e [2] be 50 [2] 83 }

  condition:
    any of them
}