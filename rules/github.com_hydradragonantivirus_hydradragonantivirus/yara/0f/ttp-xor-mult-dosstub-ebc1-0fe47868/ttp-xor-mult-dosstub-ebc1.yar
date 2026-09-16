rule TTP_XOR_MULT_DOSStub_ebc1 {
  strings:
    $key_ebc1 = { bf a9 [2] cb b1 [2] 8c b3 [2] cb a2 [2] 85 ae [2] 89 a4 [2] 9e af [2] 85 e1 [2] b8 }

  condition:
    any of them
}