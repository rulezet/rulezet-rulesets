rule TTP_XOR_WriteProcessMemory_7766 {
  strings:
    $key_7766 = { 20 14 [2] 12 36 [2] 14 03 [2] 3a 03 [2] 05 1f }

  condition:
    any of them
}