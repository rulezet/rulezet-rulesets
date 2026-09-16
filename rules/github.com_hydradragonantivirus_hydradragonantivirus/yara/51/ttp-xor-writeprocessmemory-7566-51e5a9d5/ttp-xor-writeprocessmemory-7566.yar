rule TTP_XOR_WriteProcessMemory_7566 {
  strings:
    $key_7566 = { 22 14 [2] 10 36 [2] 16 03 [2] 38 03 [2] 07 1f }

  condition:
    any of them
}