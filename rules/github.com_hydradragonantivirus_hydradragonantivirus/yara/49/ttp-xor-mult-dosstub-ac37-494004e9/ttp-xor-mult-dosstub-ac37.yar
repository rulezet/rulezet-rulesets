rule TTP_XOR_MULT_DOSStub_ac37 {
  strings:
    $key_ac37 = { f8 5f [2] 8c 47 [2] cb 45 [2] 8c 54 [2] c2 58 [2] ce 52 [2] d9 59 [2] c2 17 [2] ff }

  condition:
    any of them
}