rule TTP_XOR_WriteProcessMemory_5e30 {
  strings:
    $key_5e30 = { 09 42 [2] 3b 60 [2] 3d 55 [2] 13 55 [2] 2c 49 }

  condition:
    any of them
}