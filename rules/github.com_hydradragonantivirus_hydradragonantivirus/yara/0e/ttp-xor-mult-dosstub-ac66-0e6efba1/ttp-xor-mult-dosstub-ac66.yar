rule TTP_XOR_MULT_DOSStub_ac66 {
  strings:
    $key_ac66 = { f8 0e [2] 8c 16 [2] cb 14 [2] 8c 05 [2] c2 09 [2] ce 03 [2] d9 08 [2] c2 46 [2] ff }

  condition:
    any of them
}