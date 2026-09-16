rule TTP_XOR_MULT_DOSStub_90db {
  strings:
    $key_90db = { c4 b3 [2] b0 ab [2] f7 a9 [2] b0 b8 [2] fe b4 [2] f2 be [2] e5 b5 [2] fe fb [2] c3 }

  condition:
    any of them
}