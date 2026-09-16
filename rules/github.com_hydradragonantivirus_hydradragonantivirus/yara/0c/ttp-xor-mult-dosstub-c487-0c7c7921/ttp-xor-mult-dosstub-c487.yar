rule TTP_XOR_MULT_DOSStub_c487 {
  strings:
    $key_c487 = { 90 ef [2] e4 f7 [2] a3 f5 [2] e4 e4 [2] aa e8 [2] a6 e2 [2] b1 e9 [2] aa a7 [2] 97 }

  condition:
    any of them
}