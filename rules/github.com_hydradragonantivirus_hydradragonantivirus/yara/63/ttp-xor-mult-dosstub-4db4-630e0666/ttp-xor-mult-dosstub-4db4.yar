rule TTP_XOR_MULT_DOSStub_4db4 {
  strings:
    $key_4db4 = { 19 dc [2] 6d c4 [2] 2a c6 [2] 6d d7 [2] 23 db [2] 2f d1 [2] 38 da [2] 23 94 [2] 1e }

  condition:
    any of them
}