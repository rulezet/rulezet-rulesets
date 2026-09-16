rule TTP_XOR_MULT_DOSStub_26b2 {
  strings:
    $key_26b2 = { 72 da [2] 06 c2 [2] 41 c0 [2] 06 d1 [2] 48 dd [2] 44 d7 [2] 53 dc [2] 48 92 [2] 75 }

  condition:
    any of them
}