rule TTP_XOR_MULT_DOSStub_36b8 {
  strings:
    $key_36b8 = { 62 d0 [2] 16 c8 [2] 51 ca [2] 16 db [2] 58 d7 [2] 54 dd [2] 43 d6 [2] 58 98 [2] 65 }

  condition:
    any of them
}