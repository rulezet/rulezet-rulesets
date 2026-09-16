rule TTP_XOR_WriteProcessMemory_5e57 {
  strings:
    $key_5e57 = { 09 25 [2] 3b 07 [2] 3d 32 [2] 13 32 [2] 2c 2e }

  condition:
    any of them
}