rule TTP_XOR_MULT_DOSStub_5bdb {
  strings:
    $key_5bdb = { 0f b3 [2] 7b ab [2] 3c a9 [2] 7b b8 [2] 35 b4 [2] 39 be [2] 2e b5 [2] 35 fb [2] 08 }

  condition:
    any of them
}