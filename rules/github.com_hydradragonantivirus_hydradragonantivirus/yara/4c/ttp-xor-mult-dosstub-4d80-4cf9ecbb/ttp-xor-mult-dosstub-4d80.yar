rule TTP_XOR_MULT_DOSStub_4d80 {
  strings:
    $key_4d80 = { 19 e8 [2] 6d f0 [2] 2a f2 [2] 6d e3 [2] 23 ef [2] 2f e5 [2] 38 ee [2] 23 a0 [2] 1e }

  condition:
    any of them
}