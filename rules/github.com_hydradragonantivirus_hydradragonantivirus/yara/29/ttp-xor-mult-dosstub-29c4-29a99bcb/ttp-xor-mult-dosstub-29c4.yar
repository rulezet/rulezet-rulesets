rule TTP_XOR_MULT_DOSStub_29c4 {
  strings:
    $key_29c4 = { 7d ac [2] 09 b4 [2] 4e b6 [2] 09 a7 [2] 47 ab [2] 4b a1 [2] 5c aa [2] 47 e4 [2] 7a }

  condition:
    any of them
}