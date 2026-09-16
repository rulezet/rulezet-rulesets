rule TTP_XOR_MULT_DOSStub_ac36 {
  strings:
    $key_ac36 = { f8 5e [2] 8c 46 [2] cb 44 [2] 8c 55 [2] c2 59 [2] ce 53 [2] d9 58 [2] c2 16 [2] ff }

  condition:
    any of them
}