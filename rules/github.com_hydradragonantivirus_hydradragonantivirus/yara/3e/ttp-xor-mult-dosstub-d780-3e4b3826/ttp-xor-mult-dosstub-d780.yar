rule TTP_XOR_MULT_DOSStub_d780 {
  strings:
    $key_d780 = { 83 e8 [2] f7 f0 [2] b0 f2 [2] f7 e3 [2] b9 ef [2] b5 e5 [2] a2 ee [2] b9 a0 [2] 84 }

  condition:
    any of them
}