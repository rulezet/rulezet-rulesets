rule TTP_XOR_MULT_DOSStub_ac05 {
  strings:
    $key_ac05 = { f8 6d [2] 8c 75 [2] cb 77 [2] 8c 66 [2] c2 6a [2] ce 60 [2] d9 6b [2] c2 25 [2] ff }

  condition:
    any of them
}