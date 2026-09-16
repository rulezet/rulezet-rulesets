rule TTP_XOR_MULT_DOSStub_25b5 {
  strings:
    $key_25b5 = { 71 dd [2] 05 c5 [2] 42 c7 [2] 05 d6 [2] 4b da [2] 47 d0 [2] 50 db [2] 4b 95 [2] 76 }

  condition:
    any of them
}