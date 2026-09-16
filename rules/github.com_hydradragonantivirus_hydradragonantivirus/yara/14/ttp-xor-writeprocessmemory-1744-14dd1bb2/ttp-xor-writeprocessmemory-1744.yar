rule TTP_XOR_WriteProcessMemory_1744 {
  strings:
    $key_1744 = { 40 36 [2] 72 14 [2] 74 21 [2] 5a 21 [2] 65 3d }

  condition:
    any of them
}