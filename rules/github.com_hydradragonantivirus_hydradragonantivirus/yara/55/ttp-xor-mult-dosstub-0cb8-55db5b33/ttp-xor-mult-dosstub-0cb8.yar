rule TTP_XOR_MULT_DOSStub_0cb8 {
  strings:
    $key_0cb8 = { 58 d0 [2] 2c c8 [2] 6b ca [2] 2c db [2] 62 d7 [2] 6e dd [2] 79 d6 [2] 62 98 [2] 5f }

  condition:
    any of them
}