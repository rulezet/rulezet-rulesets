rule TTP_XOR_MULT_DOSStub_ebc5 {
  strings:
    $key_ebc5 = { bf ad [2] cb b5 [2] 8c b7 [2] cb a6 [2] 85 aa [2] 89 a0 [2] 9e ab [2] 85 e5 [2] b8 }

  condition:
    any of them
}