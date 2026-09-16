rule TTP_XOR_MULT_DOSStub_04b5 {
  strings:
    $key_04b5 = { 50 dd [2] 24 c5 [2] 63 c7 [2] 24 d6 [2] 6a da [2] 66 d0 [2] 71 db [2] 6a 95 [2] 57 }

  condition:
    any of them
}