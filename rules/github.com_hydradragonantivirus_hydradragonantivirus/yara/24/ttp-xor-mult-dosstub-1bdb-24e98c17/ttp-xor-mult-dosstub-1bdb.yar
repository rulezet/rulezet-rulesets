rule TTP_XOR_MULT_DOSStub_1bdb {
  strings:
    $key_1bdb = { 4f b3 [2] 3b ab [2] 7c a9 [2] 3b b8 [2] 75 b4 [2] 79 be [2] 6e b5 [2] 75 fb [2] 48 }

  condition:
    any of them
}