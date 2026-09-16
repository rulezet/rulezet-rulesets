rule TTP_XOR_MULT_DOSStub_76b2 {
  strings:
    $key_76b2 = { 22 da [2] 56 c2 [2] 11 c0 [2] 56 d1 [2] 18 dd [2] 14 d7 [2] 03 dc [2] 18 92 [2] 25 }

  condition:
    any of them
}