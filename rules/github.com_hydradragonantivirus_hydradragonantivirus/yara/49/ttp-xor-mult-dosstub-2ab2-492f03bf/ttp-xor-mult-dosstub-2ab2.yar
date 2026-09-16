rule TTP_XOR_MULT_DOSStub_2ab2 {
  strings:
    $key_2ab2 = { 7e da [2] 0a c2 [2] 4d c0 [2] 0a d1 [2] 44 dd [2] 48 d7 [2] 5f dc [2] 44 92 [2] 79 }

  condition:
    any of them
}