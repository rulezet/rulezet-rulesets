rule TTP_XOR_WriteProcessMemory_4f74 {
  strings:
    $key_4f74 = { 18 06 [2] 2a 24 [2] 2c 11 [2] 02 11 [2] 3d 0d }

  condition:
    any of them
}