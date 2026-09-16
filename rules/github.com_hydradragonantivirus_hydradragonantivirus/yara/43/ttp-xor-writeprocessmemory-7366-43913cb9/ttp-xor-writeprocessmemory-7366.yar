rule TTP_XOR_WriteProcessMemory_7366 {
  strings:
    $key_7366 = { 24 14 [2] 16 36 [2] 10 03 [2] 3e 03 [2] 01 1f }

  condition:
    any of them
}