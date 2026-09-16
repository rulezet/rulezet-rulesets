rule TTP_XOR_MULT_DOSStub_ac2b {
  strings:
    $key_ac2b = { f8 43 [2] 8c 5b [2] cb 59 [2] 8c 48 [2] c2 44 [2] ce 4e [2] d9 45 [2] c2 0b [2] ff }

  condition:
    any of them
}