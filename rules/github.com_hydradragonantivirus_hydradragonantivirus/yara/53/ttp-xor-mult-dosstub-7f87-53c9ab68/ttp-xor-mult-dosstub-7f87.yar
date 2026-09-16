rule TTP_XOR_MULT_DOSStub_7f87 {
  strings:
    $key_7f87 = { 2b ef [2] 5f f7 [2] 18 f5 [2] 5f e4 [2] 11 e8 [2] 1d e2 [2] 0a e9 [2] 11 a7 [2] 2c }

  condition:
    any of them
}