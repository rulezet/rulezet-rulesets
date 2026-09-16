rule TTP_XOR_MULT_DOSStub_ebc4 {
  strings:
    $key_ebc4 = { bf ac [2] cb b4 [2] 8c b6 [2] cb a7 [2] 85 ab [2] 89 a1 [2] 9e aa [2] 85 e4 [2] b8 }

  condition:
    any of them
}