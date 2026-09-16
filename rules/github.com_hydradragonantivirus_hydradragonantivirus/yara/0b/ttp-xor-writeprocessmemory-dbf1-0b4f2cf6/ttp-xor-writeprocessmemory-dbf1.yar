rule TTP_XOR_WriteProcessMemory_dbf1 {
  strings:
    $key_dbf1 = { 8c 83 [2] be a1 [2] b8 94 [2] 96 94 [2] a9 88 }

  condition:
    any of them
}