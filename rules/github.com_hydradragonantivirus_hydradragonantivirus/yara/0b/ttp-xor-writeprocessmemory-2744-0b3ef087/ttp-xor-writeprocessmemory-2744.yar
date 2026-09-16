rule TTP_XOR_WriteProcessMemory_2744 {
  strings:
    $key_2744 = { 70 36 [2] 42 14 [2] 44 21 [2] 6a 21 [2] 55 3d }

  condition:
    any of them
}