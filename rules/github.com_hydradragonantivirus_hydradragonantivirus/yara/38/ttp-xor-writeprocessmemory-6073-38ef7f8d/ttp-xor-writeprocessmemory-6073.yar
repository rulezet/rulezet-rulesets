rule TTP_XOR_WriteProcessMemory_6073 {
  strings:
    $key_6073 = { 37 01 [2] 05 23 [2] 03 16 [2] 2d 16 [2] 12 0a }

  condition:
    any of them
}