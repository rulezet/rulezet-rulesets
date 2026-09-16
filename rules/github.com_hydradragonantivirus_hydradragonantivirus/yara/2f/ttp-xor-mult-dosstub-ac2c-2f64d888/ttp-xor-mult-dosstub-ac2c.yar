rule TTP_XOR_MULT_DOSStub_ac2c {
  strings:
    $key_ac2c = { f8 44 [2] 8c 5c [2] cb 5e [2] 8c 4f [2] c2 43 [2] ce 49 [2] d9 42 [2] c2 0c [2] ff }

  condition:
    any of them
}