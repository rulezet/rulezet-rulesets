rule TTP_XOR_WriteProcessMemory_67e0 {
  strings:
    $key_67e0 = { 30 92 [2] 02 b0 [2] 04 85 [2] 2a 85 [2] 15 99 }

  condition:
    any of them
}