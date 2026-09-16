rule TTP_XOR_MULT_DOSStub_39c4 {
  strings:
    $key_39c4 = { 6d ac [2] 19 b4 [2] 5e b6 [2] 19 a7 [2] 57 ab [2] 5b a1 [2] 4c aa [2] 57 e4 [2] 6a }

  condition:
    any of them
}