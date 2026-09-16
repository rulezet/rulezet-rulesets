rule TTP_XOR_WriteProcessMemory_5e22 {
  strings:
    $key_5e22 = { 09 50 [2] 3b 72 [2] 3d 47 [2] 13 47 [2] 2c 5b }

  condition:
    any of them
}