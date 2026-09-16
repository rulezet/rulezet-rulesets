rule TTP_XOR_MULT_DOSStub_48d6 {
  strings:
    $key_48d6 = { 1c be [2] 68 a6 [2] 2f a4 [2] 68 b5 [2] 26 b9 [2] 2a b3 [2] 3d b8 [2] 26 f6 [2] 1b }

  condition:
    any of them
}