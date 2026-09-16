rule TTP_XOR_MULT_DOSStub_ac46 {
  strings:
    $key_ac46 = { f8 2e [2] 8c 36 [2] cb 34 [2] 8c 25 [2] c2 29 [2] ce 23 [2] d9 28 [2] c2 66 [2] ff }

  condition:
    any of them
}