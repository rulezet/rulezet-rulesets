rule TTP_XOR_MULT_DOSStub_3d86 {
  strings:
    $key_3d86 = { 69 ee [2] 1d f6 [2] 5a f4 [2] 1d e5 [2] 53 e9 [2] 5f e3 [2] 48 e8 [2] 53 a6 [2] 6e }

  condition:
    any of them
}