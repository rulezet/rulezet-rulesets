rule TTP_XOR_WriteProcessMemory_5e13 {
  strings:
    $key_5e13 = { 09 61 [2] 3b 43 [2] 3d 76 [2] 13 76 [2] 2c 6a }

  condition:
    any of them
}