rule TTP_XOR_MULT_DOSStub_c687 {
  strings:
    $key_c687 = { 92 ef [2] e6 f7 [2] a1 f5 [2] e6 e4 [2] a8 e8 [2] a4 e2 [2] b3 e9 [2] a8 a7 [2] 95 }

  condition:
    any of them
}