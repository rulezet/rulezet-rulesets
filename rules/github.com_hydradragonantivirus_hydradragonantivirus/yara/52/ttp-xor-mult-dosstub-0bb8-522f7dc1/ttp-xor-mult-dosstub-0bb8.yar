rule TTP_XOR_MULT_DOSStub_0bb8 {
  strings:
    $key_0bb8 = { 5f d0 [2] 2b c8 [2] 6c ca [2] 2b db [2] 65 d7 [2] 69 dd [2] 7e d6 [2] 65 98 [2] 58 }

  condition:
    any of them
}