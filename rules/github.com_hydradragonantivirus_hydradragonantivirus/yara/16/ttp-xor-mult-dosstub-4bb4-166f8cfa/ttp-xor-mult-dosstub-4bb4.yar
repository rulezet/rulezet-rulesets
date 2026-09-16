rule TTP_XOR_MULT_DOSStub_4bb4 {
  strings:
    $key_4bb4 = { 1f dc [2] 6b c4 [2] 2c c6 [2] 6b d7 [2] 25 db [2] 29 d1 [2] 3e da [2] 25 94 [2] 18 }

  condition:
    any of them
}