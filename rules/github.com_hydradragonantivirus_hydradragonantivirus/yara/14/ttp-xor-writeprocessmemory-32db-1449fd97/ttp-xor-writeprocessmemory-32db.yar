rule TTP_XOR_WriteProcessMemory_32db {
  strings:
    $key_32db = { 65 a9 [2] 57 8b [2] 51 be [2] 7f be [2] 40 a2 }

  condition:
    any of them
}