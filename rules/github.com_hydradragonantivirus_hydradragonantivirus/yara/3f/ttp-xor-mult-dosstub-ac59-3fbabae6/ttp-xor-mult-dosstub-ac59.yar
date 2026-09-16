rule TTP_XOR_MULT_DOSStub_ac59 {
  strings:
    $key_ac59 = { f8 31 [2] 8c 29 [2] cb 2b [2] 8c 3a [2] c2 36 [2] ce 3c [2] d9 37 [2] c2 79 [2] ff }

  condition:
    any of them
}