rule TTP_XOR_WriteProcessMemory_42db {
  strings:
    $key_42db = { 15 a9 [2] 27 8b [2] 21 be [2] 0f be [2] 30 a2 }

  condition:
    any of them
}