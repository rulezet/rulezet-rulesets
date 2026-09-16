rule TTP_XOR_MULT_DOSStub_ac09 {
  strings:
    $key_ac09 = { f8 61 [2] 8c 79 [2] cb 7b [2] 8c 6a [2] c2 66 [2] ce 6c [2] d9 67 [2] c2 29 [2] ff }

  condition:
    any of them
}