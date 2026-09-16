rule TTP_XOR_MULT_DOSStub_ac75 {
  strings:
    $key_ac75 = { f8 1d [2] 8c 05 [2] cb 07 [2] 8c 16 [2] c2 1a [2] ce 10 [2] d9 1b [2] c2 55 [2] ff }

  condition:
    any of them
}