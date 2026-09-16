rule TTP_XOR_MULT_DOSStub_46b5 {
  strings:
    $key_46b5 = { 12 dd [2] 66 c5 [2] 21 c7 [2] 66 d6 [2] 28 da [2] 24 d0 [2] 33 db [2] 28 95 [2] 15 }

  condition:
    any of them
}