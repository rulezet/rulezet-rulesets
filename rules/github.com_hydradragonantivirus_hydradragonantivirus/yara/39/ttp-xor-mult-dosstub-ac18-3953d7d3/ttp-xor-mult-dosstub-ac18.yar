rule TTP_XOR_MULT_DOSStub_ac18 {
  strings:
    $key_ac18 = { f8 70 [2] 8c 68 [2] cb 6a [2] 8c 7b [2] c2 77 [2] ce 7d [2] d9 76 [2] c2 38 [2] ff }

  condition:
    any of them
}