rule TTP_XOR_MULT_DOSStub_eb82 {
  strings:
    $key_eb82 = { bf ea [2] cb f2 [2] 8c f0 [2] cb e1 [2] 85 ed [2] 89 e7 [2] 9e ec [2] 85 a2 [2] b8 }

  condition:
    any of them
}