rule TTP_XOR_MULT_DOSStub_ac19 {
  strings:
    $key_ac19 = { f8 71 [2] 8c 69 [2] cb 6b [2] 8c 7a [2] c2 76 [2] ce 7c [2] d9 77 [2] c2 39 [2] ff }

  condition:
    any of them
}