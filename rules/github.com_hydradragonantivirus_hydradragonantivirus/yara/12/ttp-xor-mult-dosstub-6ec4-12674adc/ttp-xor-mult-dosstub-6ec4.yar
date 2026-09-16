rule TTP_XOR_MULT_DOSStub_6ec4 {
  strings:
    $key_6ec4 = { 3a ac [2] 4e b4 [2] 09 b6 [2] 4e a7 [2] 00 ab [2] 0c a1 [2] 1b aa [2] 00 e4 [2] 3d }

  condition:
    any of them
}