rule TTP_XOR_MULT_DOSStub_0f87 {
  strings:
    $key_0f87 = { 5b ef [2] 2f f7 [2] 68 f5 [2] 2f e4 [2] 61 e8 [2] 6d e2 [2] 7a e9 [2] 61 a7 [2] 5c }

  condition:
    any of them
}