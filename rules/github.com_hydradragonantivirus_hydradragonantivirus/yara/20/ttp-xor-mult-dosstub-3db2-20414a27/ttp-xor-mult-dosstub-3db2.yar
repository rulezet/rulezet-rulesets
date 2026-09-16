rule TTP_XOR_MULT_DOSStub_3db2 {
  strings:
    $key_3db2 = { 69 da [2] 1d c2 [2] 5a c0 [2] 1d d1 [2] 53 dd [2] 5f d7 [2] 48 dc [2] 53 92 [2] 6e }

  condition:
    any of them
}