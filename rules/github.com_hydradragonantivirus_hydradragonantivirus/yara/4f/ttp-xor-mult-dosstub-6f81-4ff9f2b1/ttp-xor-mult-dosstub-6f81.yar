rule TTP_XOR_MULT_DOSStub_6f81 {
  strings:
    $key_6f81 = { 3b e9 [2] 4f f1 [2] 08 f3 [2] 4f e2 [2] 01 ee [2] 0d e4 [2] 1a ef [2] 01 a1 [2] 3c }

  condition:
    any of them
}