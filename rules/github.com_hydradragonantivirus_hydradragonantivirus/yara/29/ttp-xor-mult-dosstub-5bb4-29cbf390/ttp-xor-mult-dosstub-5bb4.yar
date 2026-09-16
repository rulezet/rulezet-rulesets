rule TTP_XOR_MULT_DOSStub_5bb4 {
  strings:
    $key_5bb4 = { 0f dc [2] 7b c4 [2] 3c c6 [2] 7b d7 [2] 35 db [2] 39 d1 [2] 2e da [2] 35 94 [2] 08 }

  condition:
    any of them
}