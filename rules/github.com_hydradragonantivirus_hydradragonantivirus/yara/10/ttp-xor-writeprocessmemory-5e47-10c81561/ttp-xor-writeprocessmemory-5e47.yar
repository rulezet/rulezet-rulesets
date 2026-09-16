rule TTP_XOR_WriteProcessMemory_5e47 {
  strings:
    $key_5e47 = { 09 35 [2] 3b 17 [2] 3d 22 [2] 13 22 [2] 2c 3e }

  condition:
    any of them
}