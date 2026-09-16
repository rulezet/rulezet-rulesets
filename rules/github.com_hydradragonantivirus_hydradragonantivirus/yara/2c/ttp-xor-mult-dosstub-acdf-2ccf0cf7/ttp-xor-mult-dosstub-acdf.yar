rule TTP_XOR_MULT_DOSStub_acdf {
  strings:
    $key_acdf = { f8 b7 [2] 8c af [2] cb ad [2] 8c bc [2] c2 b0 [2] ce ba [2] d9 b1 [2] c2 ff [2] ff }

  condition:
    any of them
}