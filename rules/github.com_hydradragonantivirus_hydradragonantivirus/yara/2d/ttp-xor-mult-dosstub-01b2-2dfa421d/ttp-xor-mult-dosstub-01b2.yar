rule TTP_XOR_MULT_DOSStub_01b2 {
  strings:
    $key_01b2 = { 55 da [2] 21 c2 [2] 66 c0 [2] 21 d1 [2] 6f dd [2] 63 d7 [2] 74 dc [2] 6f 92 [2] 52 }

  condition:
    any of them
}