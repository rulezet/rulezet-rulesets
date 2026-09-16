rule TTP_XOR_WriteProcessMemory_4f73 {
  strings:
    $key_4f73 = { 18 01 [2] 2a 23 [2] 2c 16 [2] 02 16 [2] 3d 0a }

  condition:
    any of them
}