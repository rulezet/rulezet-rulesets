rule TTP_XOR_MULT_DOSStub_73b8 {
  strings:
    $key_73b8 = { 27 d0 [2] 53 c8 [2] 14 ca [2] 53 db [2] 1d d7 [2] 11 dd [2] 06 d6 [2] 1d 98 [2] 20 }

  condition:
    any of them
}