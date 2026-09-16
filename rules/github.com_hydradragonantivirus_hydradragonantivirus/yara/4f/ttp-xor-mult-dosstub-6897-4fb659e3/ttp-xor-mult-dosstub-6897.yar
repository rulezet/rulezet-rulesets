rule TTP_XOR_MULT_DOSStub_6897 {
  strings:
    $key_6897 = { 3c ff [2] 48 e7 [2] 0f e5 [2] 48 f4 [2] 06 f8 [2] 0a f2 [2] 1d f9 [2] 06 b7 [2] 3b }

  condition:
    any of them
}