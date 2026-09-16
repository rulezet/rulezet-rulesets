rule TTP_XOR_WriteProcessMemory_54db {
  strings:
    $key_54db = { 03 a9 [2] 31 8b [2] 37 be [2] 19 be [2] 26 a2 }

  condition:
    any of them
}