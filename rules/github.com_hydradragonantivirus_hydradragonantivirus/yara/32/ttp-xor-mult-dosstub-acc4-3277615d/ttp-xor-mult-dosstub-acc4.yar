rule TTP_XOR_MULT_DOSStub_acc4 {
  strings:
    $key_acc4 = { f8 ac [2] 8c b4 [2] cb b6 [2] 8c a7 [2] c2 ab [2] ce a1 [2] d9 aa [2] c2 e4 [2] ff }

  condition:
    any of them
}