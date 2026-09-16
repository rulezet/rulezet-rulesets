rule TTP_XOR_MULT_DOSStub_16b2 {
  strings:
    $key_16b2 = { 42 da [2] 36 c2 [2] 71 c0 [2] 36 d1 [2] 78 dd [2] 74 d7 [2] 63 dc [2] 78 92 [2] 45 }

  condition:
    any of them
}