rule TTP_XOR_WriteProcessMemory_61db {
  strings:
    $key_61db = { 36 a9 [2] 04 8b [2] 02 be [2] 2c be [2] 13 a2 }

  condition:
    any of them
}