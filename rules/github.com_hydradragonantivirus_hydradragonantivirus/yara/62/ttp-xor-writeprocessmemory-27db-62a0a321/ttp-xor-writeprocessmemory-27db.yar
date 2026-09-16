rule TTP_XOR_WriteProcessMemory_27db {
  strings:
    $key_27db = { 70 a9 [2] 42 8b [2] 44 be [2] 6a be [2] 55 a2 }

  condition:
    any of them
}