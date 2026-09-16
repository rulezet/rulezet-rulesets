rule TTP_XOR_WriteProcessMemory_e2db {
  strings:
    $key_e2db = { b5 a9 [2] 87 8b [2] 81 be [2] af be [2] 90 a2 }

  condition:
    any of them
}