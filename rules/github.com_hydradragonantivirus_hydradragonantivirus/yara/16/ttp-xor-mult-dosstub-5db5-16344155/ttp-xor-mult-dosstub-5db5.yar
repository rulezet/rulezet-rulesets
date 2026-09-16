rule TTP_XOR_MULT_DOSStub_5db5 {
  strings:
    $key_5db5 = { 09 dd [2] 7d c5 [2] 3a c7 [2] 7d d6 [2] 33 da [2] 3f d0 [2] 28 db [2] 33 95 [2] 0e }

  condition:
    any of them
}