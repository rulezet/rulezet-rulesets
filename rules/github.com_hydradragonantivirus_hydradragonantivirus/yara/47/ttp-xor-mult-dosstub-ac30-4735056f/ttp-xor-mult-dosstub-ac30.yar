rule TTP_XOR_MULT_DOSStub_ac30 {
  strings:
    $key_ac30 = { f8 58 [2] 8c 40 [2] cb 42 [2] 8c 53 [2] c2 5f [2] ce 55 [2] d9 5e [2] c2 10 [2] ff }

  condition:
    any of them
}