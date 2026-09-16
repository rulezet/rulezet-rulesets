rule TTP_XOR_MULT_DOSStub_0fdb {
  strings:
    $key_0fdb = { 5b b3 [2] 2f ab [2] 68 a9 [2] 2f b8 [2] 61 b4 [2] 6d be [2] 7a b5 [2] 61 fb [2] 5c }

  condition:
    any of them
}