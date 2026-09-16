rule TTP_XOR_MULT_DOSStub_69c7 {
  strings:
    $key_69c7 = { 3d af [2] 49 b7 [2] 0e b5 [2] 49 a4 [2] 07 a8 [2] 0b a2 [2] 1c a9 [2] 07 e7 [2] 3a }

  condition:
    any of them
}