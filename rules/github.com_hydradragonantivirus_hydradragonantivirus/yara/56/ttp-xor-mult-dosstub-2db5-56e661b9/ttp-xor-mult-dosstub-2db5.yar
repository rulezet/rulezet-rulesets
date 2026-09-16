rule TTP_XOR_MULT_DOSStub_2db5 {
  strings:
    $key_2db5 = { 79 dd [2] 0d c5 [2] 4a c7 [2] 0d d6 [2] 43 da [2] 4f d0 [2] 58 db [2] 43 95 [2] 7e }

  condition:
    any of them
}