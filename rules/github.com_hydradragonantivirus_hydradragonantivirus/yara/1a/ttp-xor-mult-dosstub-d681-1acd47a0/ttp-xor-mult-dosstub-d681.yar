rule TTP_XOR_MULT_DOSStub_d681 {
  strings:
    $key_d681 = { 82 e9 [2] f6 f1 [2] b1 f3 [2] f6 e2 [2] b8 ee [2] b4 e4 [2] a3 ef [2] b8 a1 [2] 85 }

  condition:
    any of them
}