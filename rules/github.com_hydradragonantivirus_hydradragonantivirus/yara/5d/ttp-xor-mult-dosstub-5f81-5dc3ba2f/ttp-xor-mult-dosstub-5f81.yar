rule TTP_XOR_MULT_DOSStub_5f81 {
  strings:
    $key_5f81 = { 0b e9 [2] 7f f1 [2] 38 f3 [2] 7f e2 [2] 31 ee [2] 3d e4 [2] 2a ef [2] 31 a1 [2] 0c }

  condition:
    any of them
}