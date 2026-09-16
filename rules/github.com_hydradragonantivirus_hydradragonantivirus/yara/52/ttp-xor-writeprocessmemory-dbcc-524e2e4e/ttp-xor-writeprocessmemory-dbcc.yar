rule TTP_XOR_WriteProcessMemory_dbcc {
  strings:
    $key_dbcc = { 8c be [2] be 9c [2] b8 a9 [2] 96 a9 [2] a9 b5 }

  condition:
    any of them
}