rule TTP_XOR_MULT_DOSStub_41b2 {
  strings:
    $key_41b2 = { 15 da [2] 61 c2 [2] 26 c0 [2] 61 d1 [2] 2f dd [2] 23 d7 [2] 34 dc [2] 2f 92 [2] 12 }

  condition:
    any of them
}