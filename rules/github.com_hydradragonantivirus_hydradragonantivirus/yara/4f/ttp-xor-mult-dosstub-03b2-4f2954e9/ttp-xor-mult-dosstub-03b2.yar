rule TTP_XOR_MULT_DOSStub_03b2 {
  strings:
    $key_03b2 = { 57 da [2] 23 c2 [2] 64 c0 [2] 23 d1 [2] 6d dd [2] 61 d7 [2] 76 dc [2] 6d 92 [2] 50 }

  condition:
    any of them
}