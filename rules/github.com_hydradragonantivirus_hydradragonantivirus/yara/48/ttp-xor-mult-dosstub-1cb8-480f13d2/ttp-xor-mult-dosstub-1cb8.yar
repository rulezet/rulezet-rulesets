rule TTP_XOR_MULT_DOSStub_1cb8 {
  strings:
    $key_1cb8 = { 48 d0 [2] 3c c8 [2] 7b ca [2] 3c db [2] 72 d7 [2] 7e dd [2] 69 d6 [2] 72 98 [2] 4f }

  condition:
    any of them
}