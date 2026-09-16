rule TTP_XOR_MULT_DOSStub_7f81 {
  strings:
    $key_7f81 = { 2b e9 [2] 5f f1 [2] 18 f3 [2] 5f e2 [2] 11 ee [2] 1d e4 [2] 0a ef [2] 11 a1 [2] 2c }

  condition:
    any of them
}