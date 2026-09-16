rule TTP_XOR_WriteProcessMemory_dbf9 {
  strings:
    $key_dbf9 = { 8c 8b [2] be a9 [2] b8 9c [2] 96 9c [2] a9 80 }

  condition:
    any of them
}