rule TTP_XOR_WriteProcessMemory_6040 {
  strings:
    $key_6040 = { 37 32 [2] 05 10 [2] 03 25 [2] 2d 25 [2] 12 39 }

  condition:
    any of them
}