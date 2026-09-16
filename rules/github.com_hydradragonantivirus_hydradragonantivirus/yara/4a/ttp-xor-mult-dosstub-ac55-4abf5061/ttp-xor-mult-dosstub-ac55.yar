rule TTP_XOR_MULT_DOSStub_ac55 {
  strings:
    $key_ac55 = { f8 3d [2] 8c 25 [2] cb 27 [2] 8c 36 [2] c2 3a [2] ce 30 [2] d9 3b [2] c2 75 [2] ff }

  condition:
    any of them
}