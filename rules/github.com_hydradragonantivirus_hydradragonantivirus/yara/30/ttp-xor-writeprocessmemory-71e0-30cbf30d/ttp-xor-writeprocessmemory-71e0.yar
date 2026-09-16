rule TTP_XOR_WriteProcessMemory_71e0 {
  strings:
    $key_71e0 = { 26 92 [2] 14 b0 [2] 12 85 [2] 3c 85 [2] 03 99 }

  condition:
    any of them
}