rule TTP_XOR_WriteProcessMemory_0066 {
  strings:
    $key_0066 = { 57 14 [2] 65 36 [2] 63 03 [2] 4d 03 [2] 72 1f }

  condition:
    any of them
}