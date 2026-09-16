rule TTP_XOR_WriteProcessMemory_5e25 {
  strings:
    $key_5e25 = { 09 57 [2] 3b 75 [2] 3d 40 [2] 13 40 [2] 2c 5c }

  condition:
    any of them
}