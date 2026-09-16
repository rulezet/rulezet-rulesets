rule TTP_XOR_MULT_DOSStub_ac42 {
  strings:
    $key_ac42 = { f8 2a [2] 8c 32 [2] cb 30 [2] 8c 21 [2] c2 2d [2] ce 27 [2] d9 2c [2] c2 62 [2] ff }

  condition:
    any of them
}