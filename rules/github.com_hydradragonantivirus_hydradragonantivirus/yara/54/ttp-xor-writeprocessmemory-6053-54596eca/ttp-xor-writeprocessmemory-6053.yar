rule TTP_XOR_WriteProcessMemory_6053 {
  strings:
    $key_6053 = { 37 21 [2] 05 03 [2] 03 36 [2] 2d 36 [2] 12 2a }

  condition:
    any of them
}