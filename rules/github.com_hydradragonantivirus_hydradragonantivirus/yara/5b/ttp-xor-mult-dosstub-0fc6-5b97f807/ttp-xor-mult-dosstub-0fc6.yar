rule TTP_XOR_MULT_DOSStub_0fc6 {
  strings:
    $key_0fc6 = { 5b ae [2] 2f b6 [2] 68 b4 [2] 2f a5 [2] 61 a9 [2] 6d a3 [2] 7a a8 [2] 61 e6 [2] 5c }

  condition:
    any of them
}