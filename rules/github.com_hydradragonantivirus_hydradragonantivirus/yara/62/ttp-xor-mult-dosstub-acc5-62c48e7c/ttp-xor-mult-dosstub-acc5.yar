rule TTP_XOR_MULT_DOSStub_acc5 {
  strings:
    $key_acc5 = { f8 ad [2] 8c b5 [2] cb b7 [2] 8c a6 [2] c2 aa [2] ce a0 [2] d9 ab [2] c2 e5 [2] ff }

  condition:
    any of them
}