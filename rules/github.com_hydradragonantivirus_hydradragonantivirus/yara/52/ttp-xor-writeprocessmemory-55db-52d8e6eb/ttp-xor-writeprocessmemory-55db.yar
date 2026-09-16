rule TTP_XOR_WriteProcessMemory_55db {
  strings:
    $key_55db = { 02 a9 [2] 30 8b [2] 36 be [2] 18 be [2] 27 a2 }

  condition:
    any of them
}