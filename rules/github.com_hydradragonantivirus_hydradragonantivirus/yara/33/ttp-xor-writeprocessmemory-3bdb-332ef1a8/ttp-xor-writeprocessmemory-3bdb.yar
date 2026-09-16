rule TTP_XOR_WriteProcessMemory_3bdb {
  strings:
    $key_3bdb = { 6c a9 [2] 5e 8b [2] 58 be [2] 76 be [2] 49 a2 }

  condition:
    any of them
}