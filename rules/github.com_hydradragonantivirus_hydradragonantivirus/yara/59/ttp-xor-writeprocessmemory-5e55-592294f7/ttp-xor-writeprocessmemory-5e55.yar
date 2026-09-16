rule TTP_XOR_WriteProcessMemory_5e55 {
  strings:
    $key_5e55 = { 09 27 [2] 3b 05 [2] 3d 30 [2] 13 30 [2] 2c 2c }

  condition:
    any of them
}