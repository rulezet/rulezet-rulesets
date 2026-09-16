rule TTP_XOR_WriteProcessMemory_4544 {
  strings:
    $key_4544 = { 12 36 [2] 20 14 [2] 26 21 [2] 08 21 [2] 37 3d }

  condition:
    any of them
}