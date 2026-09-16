rule TTP_XOR_MULT_DOSStub_1a80 {
  strings:
    $key_1a80 = { 4e e8 [2] 3a f0 [2] 7d f2 [2] 3a e3 [2] 74 ef [2] 78 e5 [2] 6f ee [2] 74 a0 [2] 49 }

  condition:
    any of them
}