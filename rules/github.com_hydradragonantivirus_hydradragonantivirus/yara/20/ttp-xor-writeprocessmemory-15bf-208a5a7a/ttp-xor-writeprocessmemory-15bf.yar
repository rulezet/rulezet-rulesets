rule TTP_XOR_WriteProcessMemory_15bf {
  strings:
    $key_15bf = { 42 cd [2] 70 ef [2] 76 da [2] 58 da [2] 67 c6 }

  condition:
    any of them
}