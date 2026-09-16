rule TTP_XOR_MULT_DOSStub_5a86 {
  strings:
    $key_5a86 = { 0e ee [2] 7a f6 [2] 3d f4 [2] 7a e5 [2] 34 e9 [2] 38 e3 [2] 2f e8 [2] 34 a6 [2] 09 }

  condition:
    any of them
}