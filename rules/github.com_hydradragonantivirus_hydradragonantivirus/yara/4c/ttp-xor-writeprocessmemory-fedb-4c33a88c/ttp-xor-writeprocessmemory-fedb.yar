rule TTP_XOR_WriteProcessMemory_fedb {
  strings:
    $key_fedb = { a9 a9 [2] 9b 8b [2] 9d be [2] b3 be [2] 8c a2 }

  condition:
    any of them
}