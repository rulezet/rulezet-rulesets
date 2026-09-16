rule TTP_XOR_MULT_DOSStub_05b2 {
  strings:
    $key_05b2 = { 51 da [2] 25 c2 [2] 62 c0 [2] 25 d1 [2] 6b dd [2] 67 d7 [2] 70 dc [2] 6b 92 [2] 56 }

  condition:
    any of them
}