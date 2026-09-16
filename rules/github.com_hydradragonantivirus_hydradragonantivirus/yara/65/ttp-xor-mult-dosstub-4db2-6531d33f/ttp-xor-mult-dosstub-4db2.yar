rule TTP_XOR_MULT_DOSStub_4db2 {
  strings:
    $key_4db2 = { 19 da [2] 6d c2 [2] 2a c0 [2] 6d d1 [2] 23 dd [2] 2f d7 [2] 38 dc [2] 23 92 [2] 1e }

  condition:
    any of them
}