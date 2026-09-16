rule TTP_XOR_MULT_DOSStub_15b8 {
  strings:
    $key_15b8 = { 41 d0 [2] 35 c8 [2] 72 ca [2] 35 db [2] 7b d7 [2] 77 dd [2] 60 d6 [2] 7b 98 [2] 46 }

  condition:
    any of them
}