rule TTP_XOR_WriteProcessMemory_3edb {
  strings:
    $key_3edb = { 69 a9 [2] 5b 8b [2] 5d be [2] 73 be [2] 4c a2 }

  condition:
    any of them
}