rule TTP_XOR_MULT_DOSStub_63b2 {
  strings:
    $key_63b2 = { 37 da [2] 43 c2 [2] 04 c0 [2] 43 d1 [2] 0d dd [2] 01 d7 [2] 16 dc [2] 0d 92 [2] 30 }

  condition:
    any of them
}