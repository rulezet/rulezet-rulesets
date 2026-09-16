rule TTP_XOR_MULT_DOSStub_58c2 {
  strings:
    $key_58c2 = { 0c aa [2] 78 b2 [2] 3f b0 [2] 78 a1 [2] 36 ad [2] 3a a7 [2] 2d ac [2] 36 e2 [2] 0b }

  condition:
    any of them
}