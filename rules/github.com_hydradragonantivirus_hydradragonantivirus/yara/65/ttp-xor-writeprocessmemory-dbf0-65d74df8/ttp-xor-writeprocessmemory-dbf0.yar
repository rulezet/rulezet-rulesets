rule TTP_XOR_WriteProcessMemory_dbf0 {
  strings:
    $key_dbf0 = { 8c 82 [2] be a0 [2] b8 95 [2] 96 95 [2] a9 89 }

  condition:
    any of them
}