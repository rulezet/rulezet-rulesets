rule TTP_XOR_WriteProcessMemory_75db {
  strings:
    $key_75db = { 22 a9 [2] 10 8b [2] 16 be [2] 38 be [2] 07 a2 }

  condition:
    any of them
}