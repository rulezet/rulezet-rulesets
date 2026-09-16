rule TTP_XOR_MULT_DOSStub_1f87 {
  strings:
    $key_1f87 = { 4b ef [2] 3f f7 [2] 78 f5 [2] 3f e4 [2] 71 e8 [2] 7d e2 [2] 6a e9 [2] 71 a7 [2] 4c }

  condition:
    any of them
}