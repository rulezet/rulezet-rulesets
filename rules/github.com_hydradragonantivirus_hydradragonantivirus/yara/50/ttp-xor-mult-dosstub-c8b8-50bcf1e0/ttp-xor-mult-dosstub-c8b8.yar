rule TTP_XOR_MULT_DOSStub_c8b8 {
  strings:
    $key_c8b8 = { 9c d0 [2] e8 c8 [2] af ca [2] e8 db [2] a6 d7 [2] aa dd [2] bd d6 [2] a6 98 [2] 9b }

  condition:
    any of them
}