rule TTP_XOR_MULT_DOSStub_4ec4 {
  strings:
    $key_4ec4 = { 1a ac [2] 6e b4 [2] 29 b6 [2] 6e a7 [2] 20 ab [2] 2c a1 [2] 3b aa [2] 20 e4 [2] 1d }

  condition:
    any of them
}