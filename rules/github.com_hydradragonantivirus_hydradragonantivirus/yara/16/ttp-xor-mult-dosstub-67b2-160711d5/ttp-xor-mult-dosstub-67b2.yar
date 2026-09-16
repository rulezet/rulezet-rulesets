rule TTP_XOR_MULT_DOSStub_67b2 {
  strings:
    $key_67b2 = { 33 da [2] 47 c2 [2] 00 c0 [2] 47 d1 [2] 09 dd [2] 05 d7 [2] 12 dc [2] 09 92 [2] 34 }

  condition:
    any of them
}