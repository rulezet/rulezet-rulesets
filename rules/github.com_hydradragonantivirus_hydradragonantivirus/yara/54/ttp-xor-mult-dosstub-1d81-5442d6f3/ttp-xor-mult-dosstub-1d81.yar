rule TTP_XOR_MULT_DOSStub_1d81 {
  strings:
    $key_1d81 = { 49 e9 [2] 3d f1 [2] 7a f3 [2] 3d e2 [2] 73 ee [2] 7f e4 [2] 68 ef [2] 73 a1 [2] 4e }

  condition:
    any of them
}