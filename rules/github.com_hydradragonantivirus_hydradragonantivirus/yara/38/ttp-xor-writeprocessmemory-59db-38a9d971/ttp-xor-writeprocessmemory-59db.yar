rule TTP_XOR_WriteProcessMemory_59db {
  strings:
    $key_59db = { 0e a9 [2] 3c 8b [2] 3a be [2] 14 be [2] 2b a2 }

  condition:
    any of them
}