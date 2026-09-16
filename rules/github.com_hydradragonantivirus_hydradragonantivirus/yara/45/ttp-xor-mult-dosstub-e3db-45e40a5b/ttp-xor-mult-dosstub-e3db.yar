rule TTP_XOR_MULT_DOSStub_e3db {
  strings:
    $key_e3db = { b7 b3 [2] c3 ab [2] 84 a9 [2] c3 b8 [2] 8d b4 [2] 81 be [2] 96 b5 [2] 8d fb [2] b0 }

  condition:
    any of them
}