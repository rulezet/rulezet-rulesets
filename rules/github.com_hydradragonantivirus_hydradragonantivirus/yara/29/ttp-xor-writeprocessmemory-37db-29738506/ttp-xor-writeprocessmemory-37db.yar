rule TTP_XOR_WriteProcessMemory_37db {
  strings:
    $key_37db = { 60 a9 [2] 52 8b [2] 54 be [2] 7a be [2] 45 a2 }

  condition:
    any of them
}