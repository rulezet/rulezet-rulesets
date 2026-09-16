rule TTP_XOR_MULT_DOSStub_ac85 {
  strings:
    $key_ac85 = { f8 ed [2] 8c f5 [2] cb f7 [2] 8c e6 [2] c2 ea [2] ce e0 [2] d9 eb [2] c2 a5 [2] ff }

  condition:
    any of them
}