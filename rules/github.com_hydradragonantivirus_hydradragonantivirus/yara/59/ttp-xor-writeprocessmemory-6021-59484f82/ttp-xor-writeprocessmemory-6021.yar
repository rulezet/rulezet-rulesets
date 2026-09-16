rule TTP_XOR_WriteProcessMemory_6021 {
  strings:
    $key_6021 = { 37 53 [2] 05 71 [2] 03 44 [2] 2d 44 [2] 12 58 }

  condition:
    any of them
}