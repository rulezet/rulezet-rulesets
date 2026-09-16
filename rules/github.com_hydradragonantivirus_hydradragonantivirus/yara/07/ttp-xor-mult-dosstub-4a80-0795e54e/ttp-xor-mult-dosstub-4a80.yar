rule TTP_XOR_MULT_DOSStub_4a80 {
  strings:
    $key_4a80 = { 1e e8 [2] 6a f0 [2] 2d f2 [2] 6a e3 [2] 24 ef [2] 28 e5 [2] 3f ee [2] 24 a0 [2] 19 }

  condition:
    any of them
}