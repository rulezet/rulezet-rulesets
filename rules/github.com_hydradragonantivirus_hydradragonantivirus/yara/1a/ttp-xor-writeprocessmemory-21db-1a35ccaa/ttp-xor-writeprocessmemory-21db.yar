rule TTP_XOR_WriteProcessMemory_21db {
  strings:
    $key_21db = { 76 a9 [2] 44 8b [2] 42 be [2] 6c be [2] 53 a2 }

  condition:
    any of them
}