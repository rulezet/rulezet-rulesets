rule TTP_XOR_MULT_DOSStub_50b8 {
  strings:
    $key_50b8 = { 04 d0 [2] 70 c8 [2] 37 ca [2] 70 db [2] 3e d7 [2] 32 dd [2] 25 d6 [2] 3e 98 [2] 03 }

  condition:
    any of them
}