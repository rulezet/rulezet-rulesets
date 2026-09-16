rule TTP_XOR_MULT_DOSStub_10b8 {
  strings:
    $key_10b8 = { 44 d0 [2] 30 c8 [2] 77 ca [2] 30 db [2] 7e d7 [2] 72 dd [2] 65 d6 [2] 7e 98 [2] 43 }

  condition:
    any of them
}