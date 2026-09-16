rule TTP_XOR_MULT_DOSStub_d680 {
  strings:
    $key_d680 = { 82 e8 [2] f6 f0 [2] b1 f2 [2] f6 e3 [2] b8 ef [2] b4 e5 [2] a3 ee [2] b8 a0 [2] 85 }

  condition:
    any of them
}