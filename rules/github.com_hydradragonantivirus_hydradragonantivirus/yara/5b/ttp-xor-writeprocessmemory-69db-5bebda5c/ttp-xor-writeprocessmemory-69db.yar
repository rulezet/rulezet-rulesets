rule TTP_XOR_WriteProcessMemory_69db {
  strings:
    $key_69db = { 3e a9 [2] 0c 8b [2] 0a be [2] 24 be [2] 1b a2 }

  condition:
    any of them
}