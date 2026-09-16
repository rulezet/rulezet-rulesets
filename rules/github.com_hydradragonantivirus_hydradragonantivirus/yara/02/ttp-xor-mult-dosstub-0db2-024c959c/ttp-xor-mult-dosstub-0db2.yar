rule TTP_XOR_MULT_DOSStub_0db2 {
  strings:
    $key_0db2 = { 59 da [2] 2d c2 [2] 6a c0 [2] 2d d1 [2] 63 dd [2] 6f d7 [2] 78 dc [2] 63 92 [2] 5e }

  condition:
    any of them
}