rule TTP_XOR_MULT_DOSStub_69b3 {
  strings:
    $key_69b3 = { 3d db [2] 49 c3 [2] 0e c1 [2] 49 d0 [2] 07 dc [2] 0b d6 [2] 1c dd [2] 07 93 [2] 3a }

  condition:
    any of them
}