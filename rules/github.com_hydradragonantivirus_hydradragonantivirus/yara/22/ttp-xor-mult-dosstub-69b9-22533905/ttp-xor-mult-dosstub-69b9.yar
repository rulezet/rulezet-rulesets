rule TTP_XOR_MULT_DOSStub_69b9 {
  strings:
    $key_69b9 = { 3d d1 [2] 49 c9 [2] 0e cb [2] 49 da [2] 07 d6 [2] 0b dc [2] 1c d7 [2] 07 99 [2] 3a }

  condition:
    any of them
}