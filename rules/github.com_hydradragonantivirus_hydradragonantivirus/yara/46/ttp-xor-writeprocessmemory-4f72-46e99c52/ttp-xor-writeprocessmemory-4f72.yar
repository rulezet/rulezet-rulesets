rule TTP_XOR_WriteProcessMemory_4f72 {
  strings:
    $key_4f72 = { 18 00 [2] 2a 22 [2] 2c 17 [2] 02 17 [2] 3d 0b }

  condition:
    any of them
}