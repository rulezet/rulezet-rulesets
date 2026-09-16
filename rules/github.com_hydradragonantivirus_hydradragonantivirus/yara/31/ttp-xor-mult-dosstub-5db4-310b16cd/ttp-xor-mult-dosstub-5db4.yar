rule TTP_XOR_MULT_DOSStub_5db4 {
  strings:
    $key_5db4 = { 09 dc [2] 7d c4 [2] 3a c6 [2] 7d d7 [2] 33 db [2] 3f d1 [2] 28 da [2] 33 94 [2] 0e }

  condition:
    any of them
}