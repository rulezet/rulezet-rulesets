rule TTP_XOR_MULT_DOSStub_7bb4 {
  strings:
    $key_7bb4 = { 2f dc [2] 5b c4 [2] 1c c6 [2] 5b d7 [2] 15 db [2] 19 d1 [2] 0e da [2] 15 94 [2] 28 }

  condition:
    any of them
}