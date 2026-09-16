rule TTP_XOR_MULT_DOSStub_a3db {
  strings:
    $key_a3db = { f7 b3 [2] 83 ab [2] c4 a9 [2] 83 b8 [2] cd b4 [2] c1 be [2] d6 b5 [2] cd fb [2] f0 }

  condition:
    any of them
}