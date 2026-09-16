rule TTP_XOR_WriteProcessMemory_64db {
  strings:
    $key_64db = { 33 a9 [2] 01 8b [2] 07 be [2] 29 be [2] 16 a2 }

  condition:
    any of them
}