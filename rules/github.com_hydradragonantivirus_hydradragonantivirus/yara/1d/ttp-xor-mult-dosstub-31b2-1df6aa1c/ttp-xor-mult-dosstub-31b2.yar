rule TTP_XOR_MULT_DOSStub_31b2 {
  strings:
    $key_31b2 = { 65 da [2] 11 c2 [2] 56 c0 [2] 11 d1 [2] 5f dd [2] 53 d7 [2] 44 dc [2] 5f 92 [2] 62 }

  condition:
    any of them
}