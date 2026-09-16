rule TTP_XOR_MULT_DOSStub_1d86 {
  strings:
    $key_1d86 = { 49 ee [2] 3d f6 [2] 7a f4 [2] 3d e5 [2] 73 e9 [2] 7f e3 [2] 68 e8 [2] 73 a6 [2] 4e }

  condition:
    any of them
}