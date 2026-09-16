rule TTP_XOR_MULT_DOSStub_1bb8 {
  strings:
    $key_1bb8 = { 4f d0 [2] 3b c8 [2] 7c ca [2] 3b db [2] 75 d7 [2] 79 dd [2] 6e d6 [2] 75 98 [2] 48 }

  condition:
    any of them
}