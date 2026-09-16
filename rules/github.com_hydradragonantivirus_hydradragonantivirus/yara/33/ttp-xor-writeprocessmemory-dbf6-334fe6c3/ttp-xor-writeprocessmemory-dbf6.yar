rule TTP_XOR_WriteProcessMemory_dbf6 {
  strings:
    $key_dbf6 = { 8c 84 [2] be a6 [2] b8 93 [2] 96 93 [2] a9 8f }

  condition:
    any of them
}