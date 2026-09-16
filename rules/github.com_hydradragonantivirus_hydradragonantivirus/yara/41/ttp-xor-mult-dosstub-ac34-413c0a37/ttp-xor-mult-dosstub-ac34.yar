rule TTP_XOR_MULT_DOSStub_ac34 {
  strings:
    $key_ac34 = { f8 5c [2] 8c 44 [2] cb 46 [2] 8c 57 [2] c2 5b [2] ce 51 [2] d9 5a [2] c2 14 [2] ff }

  condition:
    any of them
}