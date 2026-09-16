rule TTP_XOR_WriteProcessMemory_40db {
  strings:
    $key_40db = { 17 a9 [2] 25 8b [2] 23 be [2] 0d be [2] 32 a2 }

  condition:
    any of them
}