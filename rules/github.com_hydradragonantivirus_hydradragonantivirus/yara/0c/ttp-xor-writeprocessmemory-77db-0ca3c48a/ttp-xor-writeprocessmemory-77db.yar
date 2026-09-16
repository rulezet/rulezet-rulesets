rule TTP_XOR_WriteProcessMemory_77db {
  strings:
    $key_77db = { 20 a9 [2] 12 8b [2] 14 be [2] 3a be [2] 05 a2 }

  condition:
    any of them
}