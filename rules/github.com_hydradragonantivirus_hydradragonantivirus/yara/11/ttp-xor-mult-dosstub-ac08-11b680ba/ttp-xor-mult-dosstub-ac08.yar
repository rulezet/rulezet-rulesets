rule TTP_XOR_MULT_DOSStub_ac08 {
  strings:
    $key_ac08 = { f8 60 [2] 8c 78 [2] cb 7a [2] 8c 6b [2] c2 67 [2] ce 6d [2] d9 66 [2] c2 28 [2] ff }

  condition:
    any of them
}