rule TTP_XOR_WriteProcessMemory_4fdb {
  strings:
    $key_4fdb = { 18 a9 [2] 2a 8b [2] 2c be [2] 02 be [2] 3d a2 }

  condition:
    any of them
}