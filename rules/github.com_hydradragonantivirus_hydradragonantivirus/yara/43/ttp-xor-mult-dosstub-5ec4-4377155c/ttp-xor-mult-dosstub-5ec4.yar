rule TTP_XOR_MULT_DOSStub_5ec4 {
  strings:
    $key_5ec4 = { 0a ac [2] 7e b4 [2] 39 b6 [2] 7e a7 [2] 30 ab [2] 3c a1 [2] 2b aa [2] 30 e4 [2] 0d }

  condition:
    any of them
}