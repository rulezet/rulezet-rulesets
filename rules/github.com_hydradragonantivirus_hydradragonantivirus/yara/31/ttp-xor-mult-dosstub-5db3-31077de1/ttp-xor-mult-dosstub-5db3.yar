rule TTP_XOR_MULT_DOSStub_5db3 {
  strings:
    $key_5db3 = { 09 db [2] 7d c3 [2] 3a c1 [2] 7d d0 [2] 33 dc [2] 3f d6 [2] 28 dd [2] 33 93 [2] 0e }

  condition:
    any of them
}