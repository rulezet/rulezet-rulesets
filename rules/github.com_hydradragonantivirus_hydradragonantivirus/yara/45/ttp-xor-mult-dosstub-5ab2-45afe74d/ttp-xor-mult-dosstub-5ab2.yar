rule TTP_XOR_MULT_DOSStub_5ab2 {
  strings:
    $key_5ab2 = { 0e da [2] 7a c2 [2] 3d c0 [2] 7a d1 [2] 34 dd [2] 38 d7 [2] 2f dc [2] 34 92 [2] 09 }

  condition:
    any of them
}