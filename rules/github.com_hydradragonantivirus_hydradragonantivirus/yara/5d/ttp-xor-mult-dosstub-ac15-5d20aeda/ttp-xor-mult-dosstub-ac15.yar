rule TTP_XOR_MULT_DOSStub_ac15 {
  strings:
    $key_ac15 = { f8 7d [2] 8c 65 [2] cb 67 [2] 8c 76 [2] c2 7a [2] ce 70 [2] d9 7b [2] c2 35 [2] ff }

  condition:
    any of them
}