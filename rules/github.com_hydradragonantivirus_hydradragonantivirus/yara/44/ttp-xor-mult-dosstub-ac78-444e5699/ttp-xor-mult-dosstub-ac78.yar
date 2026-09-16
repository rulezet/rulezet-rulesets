rule TTP_XOR_MULT_DOSStub_ac78 {
  strings:
    $key_ac78 = { f8 10 [2] 8c 08 [2] cb 0a [2] 8c 1b [2] c2 17 [2] ce 1d [2] d9 16 [2] c2 58 [2] ff }

  condition:
    any of them
}