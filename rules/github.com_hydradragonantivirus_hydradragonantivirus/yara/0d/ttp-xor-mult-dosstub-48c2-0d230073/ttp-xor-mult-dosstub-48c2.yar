rule TTP_XOR_MULT_DOSStub_48c2 {
  strings:
    $key_48c2 = { 1c aa [2] 68 b2 [2] 2f b0 [2] 68 a1 [2] 26 ad [2] 2a a7 [2] 3d ac [2] 26 e2 [2] 1b }

  condition:
    any of them
}