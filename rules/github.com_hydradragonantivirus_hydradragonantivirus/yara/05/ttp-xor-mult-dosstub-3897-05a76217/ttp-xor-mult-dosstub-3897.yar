rule TTP_XOR_MULT_DOSStub_3897 {
  strings:
    $key_3897 = { 6c ff [2] 18 e7 [2] 5f e5 [2] 18 f4 [2] 56 f8 [2] 5a f2 [2] 4d f9 [2] 56 b7 [2] 6b }

  condition:
    any of them
}