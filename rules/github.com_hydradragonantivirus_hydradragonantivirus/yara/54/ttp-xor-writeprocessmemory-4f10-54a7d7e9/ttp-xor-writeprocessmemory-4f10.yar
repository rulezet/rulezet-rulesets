rule TTP_XOR_WriteProcessMemory_4f10 {
  strings:
    $key_4f10 = { 18 62 [2] 2a 40 [2] 2c 75 [2] 02 75 [2] 3d 69 }

  condition:
    any of them
}