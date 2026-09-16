rule TTP_XOR_MULT_DOSStub_58a4 {
  strings:
    $key_58a4 = { 0c cc [2] 78 d4 [2] 3f d6 [2] 78 c7 [2] 36 cb [2] 3a c1 [2] 2d ca [2] 36 84 [2] 0b }

  condition:
    any of them
}