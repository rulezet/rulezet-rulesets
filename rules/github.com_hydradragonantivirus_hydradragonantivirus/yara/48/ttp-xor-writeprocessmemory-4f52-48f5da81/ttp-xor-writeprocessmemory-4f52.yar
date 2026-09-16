rule TTP_XOR_WriteProcessMemory_4f52 {
  strings:
    $key_4f52 = { 18 20 [2] 2a 02 [2] 2c 37 [2] 02 37 [2] 3d 2b }

  condition:
    any of them
}