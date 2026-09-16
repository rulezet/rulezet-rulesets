rule TTP_XOR_WriteProcessMemory_1366 {
  strings:
    $key_1366 = { 44 14 [2] 76 36 [2] 70 03 [2] 5e 03 [2] 61 1f }

  condition:
    any of them
}