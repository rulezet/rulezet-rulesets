rule TTP_XOR_MULT_DOSStub_6ab2 {
  strings:
    $key_6ab2 = { 3e da [2] 4a c2 [2] 0d c0 [2] 4a d1 [2] 04 dd [2] 08 d7 [2] 1f dc [2] 04 92 [2] 39 }

  condition:
    any of them
}