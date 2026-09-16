rule TTP_XOR_WriteProcessMemory_dbf8 {
  strings:
    $key_dbf8 = { 8c 8a [2] be a8 [2] b8 9d [2] 96 9d [2] a9 81 }

  condition:
    any of them
}