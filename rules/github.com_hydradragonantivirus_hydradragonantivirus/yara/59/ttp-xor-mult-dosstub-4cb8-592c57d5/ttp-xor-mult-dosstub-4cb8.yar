rule TTP_XOR_MULT_DOSStub_4cb8 {
  strings:
    $key_4cb8 = { 18 d0 [2] 6c c8 [2] 2b ca [2] 6c db [2] 22 d7 [2] 2e dd [2] 39 d6 [2] 22 98 [2] 1f }

  condition:
    any of them
}