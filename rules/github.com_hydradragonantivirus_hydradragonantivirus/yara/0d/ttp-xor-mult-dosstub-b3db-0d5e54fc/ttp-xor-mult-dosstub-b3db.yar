rule TTP_XOR_MULT_DOSStub_b3db {
  strings:
    $key_b3db = { e7 b3 [2] 93 ab [2] d4 a9 [2] 93 b8 [2] dd b4 [2] d1 be [2] c6 b5 [2] dd fb [2] e0 }

  condition:
    any of them
}