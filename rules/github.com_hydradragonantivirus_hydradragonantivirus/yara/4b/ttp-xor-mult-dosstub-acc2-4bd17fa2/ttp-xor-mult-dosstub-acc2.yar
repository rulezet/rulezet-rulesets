rule TTP_XOR_MULT_DOSStub_acc2 {
  strings:
    $key_acc2 = { f8 aa [2] 8c b2 [2] cb b0 [2] 8c a1 [2] c2 ad [2] ce a7 [2] d9 ac [2] c2 e2 [2] ff }

  condition:
    any of them
}