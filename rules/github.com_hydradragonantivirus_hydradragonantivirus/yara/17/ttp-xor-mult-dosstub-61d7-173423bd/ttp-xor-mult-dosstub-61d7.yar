rule TTP_XOR_MULT_DOSStub_61d7 {
  strings:
    $key_61d7 = { 35 bf [2] 41 a7 [2] 06 a5 [2] 41 b4 [2] 0f b8 [2] 03 b2 [2] 14 b9 [2] 0f f7 [2] 32 }

  condition:
    any of them
}