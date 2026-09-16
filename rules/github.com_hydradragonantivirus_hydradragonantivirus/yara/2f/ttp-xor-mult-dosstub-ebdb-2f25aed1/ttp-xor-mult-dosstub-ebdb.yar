rule TTP_XOR_MULT_DOSStub_ebdb {
  strings:
    $key_ebdb = { bf b3 [2] cb ab [2] 8c a9 [2] cb b8 [2] 85 b4 [2] 89 be [2] 9e b5 [2] 85 fb [2] b8 }

  condition:
    any of them
}