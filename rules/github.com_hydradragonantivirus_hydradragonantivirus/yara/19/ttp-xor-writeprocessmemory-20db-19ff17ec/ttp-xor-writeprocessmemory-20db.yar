rule TTP_XOR_WriteProcessMemory_20db {
  strings:
    $key_20db = { 77 a9 [2] 45 8b [2] 43 be [2] 6d be [2] 52 a2 }

  condition:
    any of them
}