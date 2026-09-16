rule TTP_XOR_MULT_DOSStub_08c2 {
  strings:
    $key_08c2 = { 5c aa [2] 28 b2 [2] 6f b0 [2] 28 a1 [2] 66 ad [2] 6a a7 [2] 7d ac [2] 66 e2 [2] 5b }

  condition:
    any of them
}