rule TTP_XOR_MULT_DOSStub_4d86 {
  strings:
    $key_4d86 = { 19 ee [2] 6d f6 [2] 2a f4 [2] 6d e5 [2] 23 e9 [2] 2f e3 [2] 38 e8 [2] 23 a6 [2] 1e }

  condition:
    any of them
}