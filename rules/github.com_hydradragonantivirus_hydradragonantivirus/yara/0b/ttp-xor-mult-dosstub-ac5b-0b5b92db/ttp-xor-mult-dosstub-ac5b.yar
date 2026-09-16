rule TTP_XOR_MULT_DOSStub_ac5b {
  strings:
    $key_ac5b = { f8 33 [2] 8c 2b [2] cb 29 [2] 8c 38 [2] c2 34 [2] ce 3e [2] d9 35 [2] c2 7b [2] ff }

  condition:
    any of them
}