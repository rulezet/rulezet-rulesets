rule TTP_XOR_WriteProcessMemory_4744 {
  strings:
    $key_4744 = { 10 36 [2] 22 14 [2] 24 21 [2] 0a 21 [2] 35 3d }

  condition:
    any of them
}