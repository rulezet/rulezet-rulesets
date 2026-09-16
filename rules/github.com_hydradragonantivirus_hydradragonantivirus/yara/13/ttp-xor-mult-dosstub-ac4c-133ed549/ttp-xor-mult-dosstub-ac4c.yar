rule TTP_XOR_MULT_DOSStub_ac4c {
  strings:
    $key_ac4c = { f8 24 [2] 8c 3c [2] cb 3e [2] 8c 2f [2] c2 23 [2] ce 29 [2] d9 22 [2] c2 6c [2] ff }

  condition:
    any of them
}