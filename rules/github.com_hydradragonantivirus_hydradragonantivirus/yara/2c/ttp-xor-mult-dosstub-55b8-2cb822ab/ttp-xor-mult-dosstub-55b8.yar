rule TTP_XOR_MULT_DOSStub_55b8 {
  strings:
    $key_55b8 = { 01 d0 [2] 75 c8 [2] 32 ca [2] 75 db [2] 3b d7 [2] 37 dd [2] 20 d6 [2] 3b 98 [2] 06 }

  condition:
    any of them
}