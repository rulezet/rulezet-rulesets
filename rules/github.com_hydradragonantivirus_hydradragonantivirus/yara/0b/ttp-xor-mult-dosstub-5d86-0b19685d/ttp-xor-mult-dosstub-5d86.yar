rule TTP_XOR_MULT_DOSStub_5d86 {
  strings:
    $key_5d86 = { 09 ee [2] 7d f6 [2] 3a f4 [2] 7d e5 [2] 33 e9 [2] 3f e3 [2] 28 e8 [2] 33 a6 [2] 0e }

  condition:
    any of them
}