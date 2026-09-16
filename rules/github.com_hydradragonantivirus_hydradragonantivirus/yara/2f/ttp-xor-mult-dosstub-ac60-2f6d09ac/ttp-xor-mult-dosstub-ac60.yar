rule TTP_XOR_MULT_DOSStub_ac60 {
  strings:
    $key_ac60 = { f8 08 [2] 8c 10 [2] cb 12 [2] 8c 03 [2] c2 0f [2] ce 05 [2] d9 0e [2] c2 40 [2] ff }

  condition:
    any of them
}