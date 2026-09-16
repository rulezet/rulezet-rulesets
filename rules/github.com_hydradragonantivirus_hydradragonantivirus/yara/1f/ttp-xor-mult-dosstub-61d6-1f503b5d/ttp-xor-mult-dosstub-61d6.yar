rule TTP_XOR_MULT_DOSStub_61d6 {
  strings:
    $key_61d6 = { 35 be [2] 41 a6 [2] 06 a4 [2] 41 b5 [2] 0f b9 [2] 03 b3 [2] 14 b8 [2] 0f f6 [2] 32 }

  condition:
    any of them
}