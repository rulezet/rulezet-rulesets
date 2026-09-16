rule TTP_XOR_MULT_DOSStub_1ab2 {
  strings:
    $key_1ab2 = { 4e da [2] 3a c2 [2] 7d c0 [2] 3a d1 [2] 74 dd [2] 78 d7 [2] 6f dc [2] 74 92 [2] 49 }

  condition:
    any of them
}