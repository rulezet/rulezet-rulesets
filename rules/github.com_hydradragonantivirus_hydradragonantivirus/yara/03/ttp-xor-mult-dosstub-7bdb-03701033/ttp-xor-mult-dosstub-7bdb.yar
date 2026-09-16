rule TTP_XOR_MULT_DOSStub_7bdb {
  strings:
    $key_7bdb = { 2f b3 [2] 5b ab [2] 1c a9 [2] 5b b8 [2] 15 b4 [2] 19 be [2] 0e b5 [2] 15 fb [2] 28 }

  condition:
    any of them
}