rule TTP_XOR_WriteProcessMemory_79db {
  strings:
    $key_79db = { 2e a9 [2] 1c 8b [2] 1a be [2] 34 be [2] 0b a2 }

  condition:
    any of them
}