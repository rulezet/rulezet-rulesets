rule TTP_XOR_MULT_DOSStub_61c7 {
  strings:
    $key_61c7 = { 35 af [2] 41 b7 [2] 06 b5 [2] 41 a4 [2] 0f a8 [2] 03 a2 [2] 14 a9 [2] 0f e7 [2] 32 }

  condition:
    any of them
}