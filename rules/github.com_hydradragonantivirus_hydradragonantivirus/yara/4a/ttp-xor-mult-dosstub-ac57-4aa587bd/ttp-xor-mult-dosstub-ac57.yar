rule TTP_XOR_MULT_DOSStub_ac57 {
  strings:
    $key_ac57 = { f8 3f [2] 8c 27 [2] cb 25 [2] 8c 34 [2] c2 38 [2] ce 32 [2] d9 39 [2] c2 77 [2] ff }

  condition:
    any of them
}