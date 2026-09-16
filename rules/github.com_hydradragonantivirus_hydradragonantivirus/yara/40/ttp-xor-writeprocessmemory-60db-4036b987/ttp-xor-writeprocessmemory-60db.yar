rule TTP_XOR_WriteProcessMemory_60db {
  strings:
    $key_60db = { 37 a9 [2] 05 8b [2] 03 be [2] 2d be [2] 12 a2 }

  condition:
    any of them
}