rule TTP_XOR_MULT_DOSStub_61c8 {
  strings:
    $key_61c8 = { 35 a0 [2] 41 b8 [2] 06 ba [2] 41 ab [2] 0f a7 [2] 03 ad [2] 14 a6 [2] 0f e8 [2] 32 }

  condition:
    any of them
}