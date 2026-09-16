rule TTP_XOR_MULT_DOSStub_e681 {
  strings:
    $key_e681 = { b2 e9 [2] c6 f1 [2] 81 f3 [2] c6 e2 [2] 88 ee [2] 84 e4 [2] 93 ef [2] 88 a1 [2] b5 }

  condition:
    any of them
}