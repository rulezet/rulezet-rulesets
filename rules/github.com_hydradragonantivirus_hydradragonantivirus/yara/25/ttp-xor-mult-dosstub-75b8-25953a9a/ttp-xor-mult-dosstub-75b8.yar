rule TTP_XOR_MULT_DOSStub_75b8 {
  strings:
    $key_75b8 = { 21 d0 [2] 55 c8 [2] 12 ca [2] 55 db [2] 1b d7 [2] 17 dd [2] 00 d6 [2] 1b 98 [2] 26 }

  condition:
    any of them
}