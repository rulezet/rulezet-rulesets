rule TTP_XOR_MULT_DOSStub_ac29 {
  strings:
    $key_ac29 = { f8 41 [2] 8c 59 [2] cb 5b [2] 8c 4a [2] c2 46 [2] ce 4c [2] d9 47 [2] c2 09 [2] ff }

  condition:
    any of them
}