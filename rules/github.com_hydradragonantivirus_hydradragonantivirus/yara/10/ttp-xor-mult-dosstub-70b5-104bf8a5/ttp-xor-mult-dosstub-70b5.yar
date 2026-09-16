rule TTP_XOR_MULT_DOSStub_70b5 {
  strings:
    $key_70b5 = { 24 dd [2] 50 c5 [2] 17 c7 [2] 50 d6 [2] 1e da [2] 12 d0 [2] 05 db [2] 1e 95 [2] 23 }

  condition:
    any of them
}