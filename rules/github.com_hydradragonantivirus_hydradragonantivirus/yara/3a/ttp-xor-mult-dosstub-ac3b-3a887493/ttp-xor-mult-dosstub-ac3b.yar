rule TTP_XOR_MULT_DOSStub_ac3b {
  strings:
    $key_ac3b = { f8 53 [2] 8c 4b [2] cb 49 [2] 8c 58 [2] c2 54 [2] ce 5e [2] d9 55 [2] c2 1b [2] ff }

  condition:
    any of them
}