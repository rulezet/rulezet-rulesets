rule TTP_XOR_MULT_DOSStub_ac14 {
  strings:
    $key_ac14 = { f8 7c [2] 8c 64 [2] cb 66 [2] 8c 77 [2] c2 7b [2] ce 71 [2] d9 7a [2] c2 34 [2] ff }

  condition:
    any of them
}