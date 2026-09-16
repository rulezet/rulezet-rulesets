rule TTP_XOR_MULT_DOSStub_28c4 {
  strings:
    $key_28c4 = { 7c ac [2] 08 b4 [2] 4f b6 [2] 08 a7 [2] 46 ab [2] 4a a1 [2] 5d aa [2] 46 e4 [2] 7b }

  condition:
    any of them
}