rule TTP_XOR_WriteProcessMemory_3544 {
  strings:
    $key_3544 = { 62 36 [2] 50 14 [2] 56 21 [2] 78 21 [2] 47 3d }

  condition:
    any of them
}