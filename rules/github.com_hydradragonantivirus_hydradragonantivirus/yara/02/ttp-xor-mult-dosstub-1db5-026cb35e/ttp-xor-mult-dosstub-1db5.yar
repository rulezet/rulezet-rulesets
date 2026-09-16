rule TTP_XOR_MULT_DOSStub_1db5 {
  strings:
    $key_1db5 = { 49 dd [2] 3d c5 [2] 7a c7 [2] 3d d6 [2] 73 da [2] 7f d0 [2] 68 db [2] 73 95 [2] 4e }

  condition:
    any of them
}