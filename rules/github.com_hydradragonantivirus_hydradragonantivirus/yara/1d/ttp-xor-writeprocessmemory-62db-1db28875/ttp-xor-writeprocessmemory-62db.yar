rule TTP_XOR_WriteProcessMemory_62db {
  strings:
    $key_62db = { 35 a9 [2] 07 8b [2] 01 be [2] 2f be [2] 10 a2 }

  condition:
    any of them
}