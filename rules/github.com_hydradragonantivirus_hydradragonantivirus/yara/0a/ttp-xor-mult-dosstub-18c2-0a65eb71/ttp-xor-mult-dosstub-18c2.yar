rule TTP_XOR_MULT_DOSStub_18c2 {
  strings:
    $key_18c2 = { 4c aa [2] 38 b2 [2] 7f b0 [2] 38 a1 [2] 76 ad [2] 7a a7 [2] 6d ac [2] 76 e2 [2] 4b }

  condition:
    any of them
}