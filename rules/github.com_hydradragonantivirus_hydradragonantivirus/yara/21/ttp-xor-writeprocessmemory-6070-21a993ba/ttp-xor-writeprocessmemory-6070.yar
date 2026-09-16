rule TTP_XOR_WriteProcessMemory_6070 {
  strings:
    $key_6070 = { 37 02 [2] 05 20 [2] 03 15 [2] 2d 15 [2] 12 09 }

  condition:
    any of them
}