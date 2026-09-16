rule TTP_XOR_WriteProcessMemory_5ef3 {
  strings:
    $key_5ef3 = { 09 81 [2] 3b a3 [2] 3d 96 [2] 13 96 [2] 2c 8a }

  condition:
    any of them
}