rule TTP_XOR_MULT_DOSStub_ac56 {
  strings:
    $key_ac56 = { f8 3e [2] 8c 26 [2] cb 24 [2] 8c 35 [2] c2 39 [2] ce 33 [2] d9 38 [2] c2 76 [2] ff }

  condition:
    any of them
}