rule TTP_XOR_MULT_DOSStub_b1db {
  strings:
    $key_b1db = { e5 b3 [2] 91 ab [2] d6 a9 [2] 91 b8 [2] df b4 [2] d3 be [2] c4 b5 [2] df fb [2] e2 }

  condition:
    any of them
}