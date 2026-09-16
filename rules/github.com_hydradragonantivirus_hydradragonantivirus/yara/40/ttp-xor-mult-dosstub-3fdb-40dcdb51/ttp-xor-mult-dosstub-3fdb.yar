rule TTP_XOR_MULT_DOSStub_3fdb {
  strings:
    $key_3fdb = { 6b b3 [2] 1f ab [2] 58 a9 [2] 1f b8 [2] 51 b4 [2] 5d be [2] 4a b5 [2] 51 fb [2] 6c }

  condition:
    any of them
}