rule TTP_XOR_MULT_DOSStub_58a8 {
  strings:
    $key_58a8 = { 0c c0 [2] 78 d8 [2] 3f da [2] 78 cb [2] 36 c7 [2] 3a cd [2] 2d c6 [2] 36 88 [2] 0b }

  condition:
    any of them
}