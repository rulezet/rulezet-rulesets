rule TTP_XOR_MULT_DOSStub_ebdf {
  strings:
    $key_ebdf = { bf b7 [2] cb af [2] 8c ad [2] cb bc [2] 85 b0 [2] 89 ba [2] 9e b1 [2] 85 ff [2] b8 }

  condition:
    any of them
}