rule TTP_XOR_WriteProcessMemory_dbf3 {
  strings:
    $key_dbf3 = { 8c 81 [2] be a3 [2] b8 96 [2] 96 96 [2] a9 8a }

  condition:
    any of them
}