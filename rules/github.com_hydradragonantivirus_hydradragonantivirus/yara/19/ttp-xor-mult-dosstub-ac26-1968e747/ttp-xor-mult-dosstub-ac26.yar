rule TTP_XOR_MULT_DOSStub_ac26 {
  strings:
    $key_ac26 = { f8 4e [2] 8c 56 [2] cb 54 [2] 8c 45 [2] c2 49 [2] ce 43 [2] d9 48 [2] c2 06 [2] ff }

  condition:
    any of them
}