rule TTP_XOR_MULT_DOSStub_ac83 {
  strings:
    $key_ac83 = { f8 eb [2] 8c f3 [2] cb f1 [2] 8c e0 [2] c2 ec [2] ce e6 [2] d9 ed [2] c2 a3 [2] ff }

  condition:
    any of them
}