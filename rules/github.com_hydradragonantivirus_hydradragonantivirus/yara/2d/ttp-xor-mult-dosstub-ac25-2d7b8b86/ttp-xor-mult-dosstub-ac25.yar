rule TTP_XOR_MULT_DOSStub_ac25 {
  strings:
    $key_ac25 = { f8 4d [2] 8c 55 [2] cb 57 [2] 8c 46 [2] c2 4a [2] ce 40 [2] d9 4b [2] c2 05 [2] ff }

  condition:
    any of them
}