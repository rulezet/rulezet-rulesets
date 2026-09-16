rule TTP_XOR_WriteProcessMemory_04db {
  strings:
    $key_04db = { 53 a9 [2] 61 8b [2] 67 be [2] 49 be [2] 76 a2 }

  condition:
    any of them
}