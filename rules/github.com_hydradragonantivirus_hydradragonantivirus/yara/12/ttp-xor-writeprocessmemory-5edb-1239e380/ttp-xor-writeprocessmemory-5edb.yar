rule TTP_XOR_WriteProcessMemory_5edb {
  strings:
    $key_5edb = { 09 a9 [2] 3b 8b [2] 3d be [2] 13 be [2] 2c a2 }

  condition:
    any of them
}