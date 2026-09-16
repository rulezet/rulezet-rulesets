rule TTP_XOR_MULT_DOSStub_4ab2 {
  strings:
    $key_4ab2 = { 1e da [2] 6a c2 [2] 2d c0 [2] 6a d1 [2] 24 dd [2] 28 d7 [2] 3f dc [2] 24 92 [2] 19 }

  condition:
    any of them
}