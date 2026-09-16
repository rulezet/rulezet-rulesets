rule TTP_XOR_MULT_DOSStub_d0e6 {
  strings:
    $key_d0e6 = { 84 8e [2] f0 96 [2] b7 94 [2] f0 85 [2] be 89 [2] b2 83 [2] a5 88 [2] be c6 [2] 83 }

  condition:
    any of them
}