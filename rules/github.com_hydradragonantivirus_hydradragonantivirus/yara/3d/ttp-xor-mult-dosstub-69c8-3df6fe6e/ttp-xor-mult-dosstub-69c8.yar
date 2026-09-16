rule TTP_XOR_MULT_DOSStub_69c8 {
  strings:
    $key_69c8 = { 3d a0 [2] 49 b8 [2] 0e ba [2] 49 ab [2] 07 a7 [2] 0b ad [2] 1c a6 [2] 07 e8 [2] 3a }

  condition:
    any of them
}