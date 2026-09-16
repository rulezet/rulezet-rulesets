rule TTP_XOR_MULT_DOSStub_5a87 {
  strings:
    $key_5a87 = { 0e ef [2] 7a f7 [2] 3d f5 [2] 7a e4 [2] 34 e8 [2] 38 e2 [2] 2f e9 [2] 34 a7 [2] 09 }

  condition:
    any of them
}