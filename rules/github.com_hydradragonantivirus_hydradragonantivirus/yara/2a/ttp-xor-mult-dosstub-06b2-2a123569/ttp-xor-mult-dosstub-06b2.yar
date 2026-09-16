rule TTP_XOR_MULT_DOSStub_06b2 {
  strings:
    $key_06b2 = { 52 da [2] 26 c2 [2] 61 c0 [2] 26 d1 [2] 68 dd [2] 64 d7 [2] 73 dc [2] 68 92 [2] 55 }

  condition:
    any of them
}