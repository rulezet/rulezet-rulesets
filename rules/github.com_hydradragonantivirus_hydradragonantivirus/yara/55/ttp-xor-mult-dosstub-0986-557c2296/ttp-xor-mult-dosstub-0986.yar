rule TTP_XOR_MULT_DOSStub_0986 {
  strings:
    $key_0986 = { 5d ee [2] 29 f6 [2] 6e f4 [2] 29 e5 [2] 67 e9 [2] 6b e3 [2] 7c e8 [2] 67 a6 [2] 5a }

  condition:
    any of them
}