rule TTP_XOR_WriteProcessMemory_7116 {
  strings:
    $key_7116 = { 26 64 [2] 14 46 [2] 12 73 [2] 3c 73 [2] 03 6f }

  condition:
    any of them
}