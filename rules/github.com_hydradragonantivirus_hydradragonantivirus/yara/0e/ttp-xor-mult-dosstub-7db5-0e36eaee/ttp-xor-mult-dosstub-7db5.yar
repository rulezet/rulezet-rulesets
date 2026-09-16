rule TTP_XOR_MULT_DOSStub_7db5 {
  strings:
    $key_7db5 = { 29 dd [2] 5d c5 [2] 1a c7 [2] 5d d6 [2] 13 da [2] 1f d0 [2] 08 db [2] 13 95 [2] 2e }

  condition:
    any of them
}