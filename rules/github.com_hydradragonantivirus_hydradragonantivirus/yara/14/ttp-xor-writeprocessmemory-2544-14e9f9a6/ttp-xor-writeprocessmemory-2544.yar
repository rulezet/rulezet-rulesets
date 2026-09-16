rule TTP_XOR_WriteProcessMemory_2544 {
  strings:
    $key_2544 = { 72 36 [2] 40 14 [2] 46 21 [2] 68 21 [2] 57 3d }

  condition:
    any of them
}