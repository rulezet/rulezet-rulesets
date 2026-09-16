rule TTP_XOR_MULT_DOSStub_09c4 {
  strings:
    $key_09c4 = { 5d ac [2] 29 b4 [2] 6e b6 [2] 29 a7 [2] 67 ab [2] 6b a1 [2] 7c aa [2] 67 e4 [2] 5a }

  condition:
    any of them
}