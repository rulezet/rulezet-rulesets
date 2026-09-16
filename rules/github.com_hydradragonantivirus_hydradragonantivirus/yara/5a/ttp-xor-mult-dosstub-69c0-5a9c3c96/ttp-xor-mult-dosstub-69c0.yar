rule TTP_XOR_MULT_DOSStub_69c0 {
  strings:
    $key_69c0 = { 3d a8 [2] 49 b0 [2] 0e b2 [2] 49 a3 [2] 07 af [2] 0b a5 [2] 1c ae [2] 07 e0 [2] 3a }

  condition:
    any of them
}