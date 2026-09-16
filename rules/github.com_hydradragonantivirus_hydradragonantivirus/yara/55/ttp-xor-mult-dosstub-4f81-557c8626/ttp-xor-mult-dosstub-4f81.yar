rule TTP_XOR_MULT_DOSStub_4f81 {
  strings:
    $key_4f81 = { 1b e9 [2] 6f f1 [2] 28 f3 [2] 6f e2 [2] 21 ee [2] 2d e4 [2] 3a ef [2] 21 a1 [2] 1c }

  condition:
    any of them
}