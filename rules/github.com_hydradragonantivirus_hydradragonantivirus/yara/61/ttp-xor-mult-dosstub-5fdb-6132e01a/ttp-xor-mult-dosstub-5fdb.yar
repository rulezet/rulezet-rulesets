rule TTP_XOR_MULT_DOSStub_5fdb {
  strings:
    $key_5fdb = { 0b b3 [2] 7f ab [2] 38 a9 [2] 7f b8 [2] 31 b4 [2] 3d be [2] 2a b5 [2] 31 fb [2] 0c }

  condition:
    any of them
}