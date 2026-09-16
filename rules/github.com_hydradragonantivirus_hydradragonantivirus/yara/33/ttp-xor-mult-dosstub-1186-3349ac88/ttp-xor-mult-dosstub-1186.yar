rule TTP_XOR_MULT_DOSStub_1186 {
  strings:
    $key_1186 = { 45 ee [2] 31 f6 [2] 76 f4 [2] 31 e5 [2] 7f e9 [2] 73 e3 [2] 64 e8 [2] 7f a6 [2] 42 }

  condition:
    any of them
}