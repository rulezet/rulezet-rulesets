rule TTP_XOR_MULT_DOSStub_44b2 {
  strings:
    $key_44b2 = { 10 da [2] 64 c2 [2] 23 c0 [2] 64 d1 [2] 2a dd [2] 26 d7 [2] 31 dc [2] 2a 92 [2] 17 }

  condition:
    any of them
}