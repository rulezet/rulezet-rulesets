rule TTP_XOR_MULT_DOSStub_44b9 {
  strings:
    $key_44b9 = { 10 d1 [2] 64 c9 [2] 23 cb [2] 64 da [2] 2a d6 [2] 26 dc [2] 31 d7 [2] 2a 99 [2] 17 }

  condition:
    any of them
}