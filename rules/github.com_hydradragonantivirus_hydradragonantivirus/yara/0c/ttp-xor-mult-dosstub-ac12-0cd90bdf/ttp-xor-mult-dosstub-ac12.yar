rule TTP_XOR_MULT_DOSStub_ac12 {
  strings:
    $key_ac12 = { f8 7a [2] 8c 62 [2] cb 60 [2] 8c 71 [2] c2 7d [2] ce 77 [2] d9 7c [2] c2 32 [2] ff }

  condition:
    any of them
}