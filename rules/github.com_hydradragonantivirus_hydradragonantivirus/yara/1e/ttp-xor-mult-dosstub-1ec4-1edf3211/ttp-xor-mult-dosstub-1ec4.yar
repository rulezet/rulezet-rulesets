rule TTP_XOR_MULT_DOSStub_1ec4 {
  strings:
    $key_1ec4 = { 4a ac [2] 3e b4 [2] 79 b6 [2] 3e a7 [2] 70 ab [2] 7c a1 [2] 6b aa [2] 70 e4 [2] 4d }

  condition:
    any of them
}