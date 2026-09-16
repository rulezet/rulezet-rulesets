rule TTP_XOR_MULT_DOSStub_0bb4 {
  strings:
    $key_0bb4 = { 5f dc [2] 2b c4 [2] 6c c6 [2] 2b d7 [2] 65 db [2] 69 d1 [2] 7e da [2] 65 94 [2] 58 }

  condition:
    any of them
}