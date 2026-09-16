rule TTP_XOR_MULT_DOSStub_7d80 {
  strings:
    $key_7d80 = { 29 e8 [2] 5d f0 [2] 1a f2 [2] 5d e3 [2] 13 ef [2] 1f e5 [2] 08 ee [2] 13 a0 [2] 2e }

  condition:
    any of them
}