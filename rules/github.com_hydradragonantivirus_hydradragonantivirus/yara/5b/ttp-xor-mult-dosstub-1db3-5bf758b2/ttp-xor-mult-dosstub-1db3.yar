rule TTP_XOR_MULT_DOSStub_1db3 {
  strings:
    $key_1db3 = { 49 db [2] 3d c3 [2] 7a c1 [2] 3d d0 [2] 73 dc [2] 7f d6 [2] 68 dd [2] 73 93 [2] 4e }

  condition:
    any of them
}