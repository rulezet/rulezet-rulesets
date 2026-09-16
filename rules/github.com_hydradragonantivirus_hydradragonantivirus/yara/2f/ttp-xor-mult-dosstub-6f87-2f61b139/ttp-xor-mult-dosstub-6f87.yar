rule TTP_XOR_MULT_DOSStub_6f87 {
  strings:
    $key_6f87 = { 3b ef [2] 4f f7 [2] 08 f5 [2] 4f e4 [2] 01 e8 [2] 0d e2 [2] 1a e9 [2] 01 a7 [2] 3c }

  condition:
    any of them
}