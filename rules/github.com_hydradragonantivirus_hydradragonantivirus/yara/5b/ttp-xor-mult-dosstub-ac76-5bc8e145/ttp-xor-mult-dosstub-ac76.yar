rule TTP_XOR_MULT_DOSStub_ac76 {
  strings:
    $key_ac76 = { f8 1e [2] 8c 06 [2] cb 04 [2] 8c 15 [2] c2 19 [2] ce 13 [2] d9 18 [2] c2 56 [2] ff }

  condition:
    any of them
}