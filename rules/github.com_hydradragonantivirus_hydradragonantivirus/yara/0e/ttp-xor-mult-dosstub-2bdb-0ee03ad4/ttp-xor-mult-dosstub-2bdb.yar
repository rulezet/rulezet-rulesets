rule TTP_XOR_MULT_DOSStub_2bdb {
  strings:
    $key_2bdb = { 7f b3 [2] 0b ab [2] 4c a9 [2] 0b b8 [2] 45 b4 [2] 49 be [2] 5e b5 [2] 45 fb [2] 78 }

  condition:
    any of them
}