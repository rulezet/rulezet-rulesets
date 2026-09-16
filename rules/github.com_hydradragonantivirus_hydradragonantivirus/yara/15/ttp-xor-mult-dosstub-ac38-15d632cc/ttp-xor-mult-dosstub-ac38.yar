rule TTP_XOR_MULT_DOSStub_ac38 {
  strings:
    $key_ac38 = { f8 50 [2] 8c 48 [2] cb 4a [2] 8c 5b [2] c2 57 [2] ce 5d [2] d9 56 [2] c2 18 [2] ff }

  condition:
    any of them
}