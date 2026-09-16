rule TTP_XOR_WriteProcessMemory_0744 {
  strings:
    $key_0744 = { 50 36 [2] 62 14 [2] 64 21 [2] 4a 21 [2] 75 3d }

  condition:
    any of them
}