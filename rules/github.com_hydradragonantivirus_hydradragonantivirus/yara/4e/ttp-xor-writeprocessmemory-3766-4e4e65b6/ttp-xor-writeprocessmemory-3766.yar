rule TTP_XOR_WriteProcessMemory_3766 {
  strings:
    $key_3766 = { 60 14 [2] 52 36 [2] 54 03 [2] 7a 03 [2] 45 1f }

  condition:
    any of them
}