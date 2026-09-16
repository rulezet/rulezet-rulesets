rule TTP_XOR_MULT_DOSStub_2bb4 {
  strings:
    $key_2bb4 = { 7f dc [2] 0b c4 [2] 4c c6 [2] 0b d7 [2] 45 db [2] 49 d1 [2] 5e da [2] 45 94 [2] 78 }

  condition:
    any of them
}