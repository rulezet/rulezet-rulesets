rule TTP_XOR_MULT_DOSStub_acd8 {
  strings:
    $key_acd8 = { f8 b0 [2] 8c a8 [2] cb aa [2] 8c bb [2] c2 b7 [2] ce bd [2] d9 b6 [2] c2 f8 [2] ff }

  condition:
    any of them
}