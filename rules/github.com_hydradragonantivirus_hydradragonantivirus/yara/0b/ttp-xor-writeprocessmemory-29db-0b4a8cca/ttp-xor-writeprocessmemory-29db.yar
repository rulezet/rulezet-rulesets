rule TTP_XOR_WriteProcessMemory_29db {
  strings:
    $key_29db = { 7e a9 [2] 4c 8b [2] 4a be [2] 64 be [2] 5b a2 }

  condition:
    any of them
}