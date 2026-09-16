rule TTP_XOR_MULT_DOSStub_ac27 {
  strings:
    $key_ac27 = { f8 4f [2] 8c 57 [2] cb 55 [2] 8c 44 [2] c2 48 [2] ce 42 [2] d9 49 [2] c2 07 [2] ff }

  condition:
    any of them
}