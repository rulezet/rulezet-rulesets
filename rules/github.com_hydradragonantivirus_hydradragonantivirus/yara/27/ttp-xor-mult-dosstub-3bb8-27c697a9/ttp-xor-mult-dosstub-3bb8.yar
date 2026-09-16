rule TTP_XOR_MULT_DOSStub_3bb8 {
  strings:
    $key_3bb8 = { 6f d0 [2] 1b c8 [2] 5c ca [2] 1b db [2] 55 d7 [2] 59 dd [2] 4e d6 [2] 55 98 [2] 68 }

  condition:
    any of them
}