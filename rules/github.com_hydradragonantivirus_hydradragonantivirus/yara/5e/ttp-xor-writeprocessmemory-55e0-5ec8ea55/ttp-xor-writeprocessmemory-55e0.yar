rule TTP_XOR_WriteProcessMemory_55e0 {
  strings:
    $key_55e0 = { 02 92 [2] 30 b0 [2] 36 85 [2] 18 85 [2] 27 99 }

  condition:
    any of them
}