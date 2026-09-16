rule TTP_XOR_MULT_DOSStub_40b8 {
  strings:
    $key_40b8 = { 14 d0 [2] 60 c8 [2] 27 ca [2] 60 db [2] 2e d7 [2] 22 dd [2] 35 d6 [2] 2e 98 [2] 13 }

  condition:
    any of them
}