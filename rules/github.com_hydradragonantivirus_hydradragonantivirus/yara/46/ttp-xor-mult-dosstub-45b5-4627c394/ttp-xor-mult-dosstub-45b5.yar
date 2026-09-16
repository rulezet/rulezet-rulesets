rule TTP_XOR_MULT_DOSStub_45b5 {
  strings:
    $key_45b5 = { 11 dd [2] 65 c5 [2] 22 c7 [2] 65 d6 [2] 2b da [2] 27 d0 [2] 30 db [2] 2b 95 [2] 16 }

  condition:
    any of them
}