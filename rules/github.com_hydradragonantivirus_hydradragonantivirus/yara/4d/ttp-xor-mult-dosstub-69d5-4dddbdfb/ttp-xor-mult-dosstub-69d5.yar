rule TTP_XOR_MULT_DOSStub_69d5 {
  strings:
    $key_69d5 = { 3d bd [2] 49 a5 [2] 0e a7 [2] 49 b6 [2] 07 ba [2] 0b b0 [2] 1c bb [2] 07 f5 [2] 3a }

  condition:
    any of them
}