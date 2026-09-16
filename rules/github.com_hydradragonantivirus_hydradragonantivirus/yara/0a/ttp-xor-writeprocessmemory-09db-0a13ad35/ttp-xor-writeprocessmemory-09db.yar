rule TTP_XOR_WriteProcessMemory_09db {
  strings:
    $key_09db = { 5e a9 [2] 6c 8b [2] 6a be [2] 44 be [2] 7b a2 }

  condition:
    any of them
}