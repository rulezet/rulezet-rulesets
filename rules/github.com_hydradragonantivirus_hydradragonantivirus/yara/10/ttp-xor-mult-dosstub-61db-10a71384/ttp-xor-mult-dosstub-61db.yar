rule TTP_XOR_MULT_DOSStub_61db {
  strings:
    $key_61db = { 35 b3 [2] 41 ab [2] 06 a9 [2] 41 b8 [2] 0f b4 [2] 03 be [2] 14 b5 [2] 0f fb [2] 32 }

  condition:
    any of them
}