rule TTP_XOR_MULT_DOSStub_1db4 {
  strings:
    $key_1db4 = { 49 dc [2] 3d c4 [2] 7a c6 [2] 3d d7 [2] 73 db [2] 7f d1 [2] 68 da [2] 73 94 [2] 4e }

  condition:
    any of them
}