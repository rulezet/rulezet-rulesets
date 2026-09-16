rule TTP_XOR_MULT_DOSStub_2db3 {
  strings:
    $key_2db3 = { 79 db [2] 0d c3 [2] 4a c1 [2] 0d d0 [2] 43 dc [2] 4f d6 [2] 58 dd [2] 43 93 [2] 7e }

  condition:
    any of them
}