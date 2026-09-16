rule TTP_XOR_WriteProcessMemory_4f41 {
  strings:
    $key_4f41 = { 18 33 [2] 2a 11 [2] 2c 24 [2] 02 24 [2] 3d 38 }

  condition:
    any of them
}