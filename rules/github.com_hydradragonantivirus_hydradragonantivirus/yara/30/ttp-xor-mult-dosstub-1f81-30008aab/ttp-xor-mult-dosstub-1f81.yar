rule TTP_XOR_MULT_DOSStub_1f81 {
  strings:
    $key_1f81 = { 4b e9 [2] 3f f1 [2] 78 f3 [2] 3f e2 [2] 71 ee [2] 7d e4 [2] 6a ef [2] 71 a1 [2] 4c }

  condition:
    any of them
}