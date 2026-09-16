rule TTP_XOR_MULT_DOSStub_77b5 {
  strings:
    $key_77b5 = { 23 dd [2] 57 c5 [2] 10 c7 [2] 57 d6 [2] 19 da [2] 15 d0 [2] 02 db [2] 19 95 [2] 24 }

  condition:
    any of them
}