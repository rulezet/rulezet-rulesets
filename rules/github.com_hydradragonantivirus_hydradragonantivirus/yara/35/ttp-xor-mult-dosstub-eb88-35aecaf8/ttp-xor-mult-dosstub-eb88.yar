rule TTP_XOR_MULT_DOSStub_eb88 {
  strings:
    $key_eb88 = { bf e0 [2] cb f8 [2] 8c fa [2] cb eb [2] 85 e7 [2] 89 ed [2] 9e e6 [2] 85 a8 [2] b8 }

  condition:
    any of them
}