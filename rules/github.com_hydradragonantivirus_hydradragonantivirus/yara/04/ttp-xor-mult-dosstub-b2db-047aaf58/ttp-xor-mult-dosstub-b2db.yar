rule TTP_XOR_MULT_DOSStub_b2db {
  strings:
    $key_b2db = { e6 b3 [2] 92 ab [2] d5 a9 [2] 92 b8 [2] dc b4 [2] d0 be [2] c7 b5 [2] dc fb [2] e1 }

  condition:
    any of them
}