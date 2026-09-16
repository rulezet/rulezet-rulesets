rule TTP_XOR_MULT_DOSStub_70b8 {
  strings:
    $key_70b8 = { 24 d0 [2] 50 c8 [2] 17 ca [2] 50 db [2] 1e d7 [2] 12 dd [2] 05 d6 [2] 1e 98 [2] 23 }

  condition:
    any of them
}