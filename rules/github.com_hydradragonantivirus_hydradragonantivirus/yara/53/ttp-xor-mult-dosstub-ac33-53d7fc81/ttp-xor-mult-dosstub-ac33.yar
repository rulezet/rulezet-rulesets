rule TTP_XOR_MULT_DOSStub_ac33 {
  strings:
    $key_ac33 = { f8 5b [2] 8c 43 [2] cb 41 [2] 8c 50 [2] c2 5c [2] ce 56 [2] d9 5d [2] c2 13 [2] ff }

  condition:
    any of them
}