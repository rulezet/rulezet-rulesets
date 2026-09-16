rule TTP_XOR_MULT_DOSStub_0587 {
  strings:
    $key_0587 = { 51 ef [2] 25 f7 [2] 62 f5 [2] 25 e4 [2] 6b e8 [2] 67 e2 [2] 70 e9 [2] 6b a7 [2] 56 }

  condition:
    any of them
}