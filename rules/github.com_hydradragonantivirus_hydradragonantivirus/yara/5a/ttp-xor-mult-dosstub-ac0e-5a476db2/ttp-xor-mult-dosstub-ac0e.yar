rule TTP_XOR_MULT_DOSStub_ac0e {
  strings:
    $key_ac0e = { f8 66 [2] 8c 7e [2] cb 7c [2] 8c 6d [2] c2 61 [2] ce 6b [2] d9 60 [2] c2 2e [2] ff }

  condition:
    any of them
}