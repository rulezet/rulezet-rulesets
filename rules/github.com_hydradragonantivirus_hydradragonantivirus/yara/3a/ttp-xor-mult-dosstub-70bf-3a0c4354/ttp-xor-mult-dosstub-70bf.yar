rule TTP_XOR_MULT_DOSStub_70bf {
  strings:
    $key_70bf = { 24 d7 [2] 50 cf [2] 17 cd [2] 50 dc [2] 1e d0 [2] 12 da [2] 05 d1 [2] 1e 9f [2] 23 }

  condition:
    any of them
}