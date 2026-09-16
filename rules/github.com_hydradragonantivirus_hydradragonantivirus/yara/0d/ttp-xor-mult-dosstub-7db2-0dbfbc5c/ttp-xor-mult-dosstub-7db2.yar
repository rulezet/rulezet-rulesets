rule TTP_XOR_MULT_DOSStub_7db2 {
  strings:
    $key_7db2 = { 29 da [2] 5d c2 [2] 1a c0 [2] 5d d1 [2] 13 dd [2] 1f d7 [2] 08 dc [2] 13 92 [2] 2e }

  condition:
    any of them
}