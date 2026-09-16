rule TTP_XOR_WriteProcessMemory_5e37 {
  strings:
    $key_5e37 = { 09 45 [2] 3b 67 [2] 3d 52 [2] 13 52 [2] 2c 4e }

  condition:
    any of them
}