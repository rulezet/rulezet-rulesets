rule TTP_XOR_WriteProcessMemory_5e32 {
  strings:
    $key_5e32 = { 09 40 [2] 3b 62 [2] 3d 57 [2] 13 57 [2] 2c 4b }

  condition:
    any of them
}