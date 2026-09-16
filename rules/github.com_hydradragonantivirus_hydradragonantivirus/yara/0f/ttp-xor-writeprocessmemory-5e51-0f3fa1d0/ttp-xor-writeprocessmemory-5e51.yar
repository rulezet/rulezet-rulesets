rule TTP_XOR_WriteProcessMemory_5e51 {
  strings:
    $key_5e51 = { 09 23 [2] 3b 01 [2] 3d 34 [2] 13 34 [2] 2c 28 }

  condition:
    any of them
}