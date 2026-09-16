rule TTP_XOR_WriteProcessMemory_2566 {
  strings:
    $key_2566 = { 72 14 [2] 40 36 [2] 46 03 [2] 68 03 [2] 57 1f }

  condition:
    any of them
}