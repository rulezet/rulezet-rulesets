rule TTP_XOR_MULT_DOSStub_4986 {
  strings:
    $key_4986 = { 1d ee [2] 69 f6 [2] 2e f4 [2] 69 e5 [2] 27 e9 [2] 2b e3 [2] 3c e8 [2] 27 a6 [2] 1a }

  condition:
    any of them
}