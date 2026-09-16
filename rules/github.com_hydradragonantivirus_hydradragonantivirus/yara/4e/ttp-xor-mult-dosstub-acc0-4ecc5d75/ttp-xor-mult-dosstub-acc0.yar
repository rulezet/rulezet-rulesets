rule TTP_XOR_MULT_DOSStub_acc0 {
  strings:
    $key_acc0 = { f8 a8 [2] 8c b0 [2] cb b2 [2] 8c a3 [2] c2 af [2] ce a5 [2] d9 ae [2] c2 e0 [2] ff }

  condition:
    any of them
}