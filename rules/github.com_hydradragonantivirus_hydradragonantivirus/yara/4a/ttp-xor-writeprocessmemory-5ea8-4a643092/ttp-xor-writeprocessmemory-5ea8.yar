rule TTP_XOR_WriteProcessMemory_5ea8 {
  strings:
    $key_5ea8 = { 09 da [2] 3b f8 [2] 3d cd [2] 13 cd [2] 2c d1 }

  condition:
    any of them
}