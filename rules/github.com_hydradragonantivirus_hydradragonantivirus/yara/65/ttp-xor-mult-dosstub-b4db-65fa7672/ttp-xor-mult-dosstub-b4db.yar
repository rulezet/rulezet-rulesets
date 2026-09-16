rule TTP_XOR_MULT_DOSStub_b4db {
  strings:
    $key_b4db = { e0 b3 [2] 94 ab [2] d3 a9 [2] 94 b8 [2] da b4 [2] d6 be [2] c1 b5 [2] da fb [2] e7 }

  condition:
    any of them
}