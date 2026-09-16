rule TTP_XOR_MULT_DOSStub_ac22 {
  strings:
    $key_ac22 = { f8 4a [2] 8c 52 [2] cb 50 [2] 8c 41 [2] c2 4d [2] ce 47 [2] d9 4c [2] c2 02 [2] ff }

  condition:
    any of them
}