rule TTP_XOR_MULT_DOSStub_30b8 {
  strings:
    $key_30b8 = { 64 d0 [2] 10 c8 [2] 57 ca [2] 10 db [2] 5e d7 [2] 52 dd [2] 45 d6 [2] 5e 98 [2] 63 }

  condition:
    any of them
}