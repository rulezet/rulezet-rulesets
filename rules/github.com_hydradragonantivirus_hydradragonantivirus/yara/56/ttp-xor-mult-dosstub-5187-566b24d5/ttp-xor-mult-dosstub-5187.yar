rule TTP_XOR_MULT_DOSStub_5187 {
  strings:
    $key_5187 = { 05 ef [2] 71 f7 [2] 36 f5 [2] 71 e4 [2] 3f e8 [2] 33 e2 [2] 24 e9 [2] 3f a7 [2] 02 }

  condition:
    any of them
}