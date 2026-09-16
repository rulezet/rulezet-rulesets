rule TTP_XOR_MULT_DOSStub_3fc4 {
  strings:
    $key_3fc4 = { 6b ac [2] 1f b4 [2] 58 b6 [2] 1f a7 [2] 51 ab [2] 5d a1 [2] 4a aa [2] 51 e4 [2] 6c }

  condition:
    any of them
}