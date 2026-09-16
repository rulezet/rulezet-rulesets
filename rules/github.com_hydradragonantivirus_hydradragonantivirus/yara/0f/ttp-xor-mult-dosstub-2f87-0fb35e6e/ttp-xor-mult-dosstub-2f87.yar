rule TTP_XOR_MULT_DOSStub_2f87 {
  strings:
    $key_2f87 = { 7b ef [2] 0f f7 [2] 48 f5 [2] 0f e4 [2] 41 e8 [2] 4d e2 [2] 5a e9 [2] 41 a7 [2] 7c }

  condition:
    any of them
}