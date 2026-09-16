rule TTP_XOR_WriteProcessMemory_12db {
  strings:
    $key_12db = { 45 a9 [2] 77 8b [2] 71 be [2] 5f be [2] 60 a2 }

  condition:
    any of them
}