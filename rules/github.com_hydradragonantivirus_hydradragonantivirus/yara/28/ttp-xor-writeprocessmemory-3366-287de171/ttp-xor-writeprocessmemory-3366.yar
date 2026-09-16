rule TTP_XOR_WriteProcessMemory_3366 {
  strings:
    $key_3366 = { 64 14 [2] 56 36 [2] 50 03 [2] 7e 03 [2] 41 1f }

  condition:
    any of them
}