rule TTP_XOR_MULT_DOSStub_35b5 {
  strings:
    $key_35b5 = { 61 dd [2] 15 c5 [2] 52 c7 [2] 15 d6 [2] 5b da [2] 57 d0 [2] 40 db [2] 5b 95 [2] 66 }

  condition:
    any of them
}