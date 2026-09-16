rule TTP_XOR_WriteProcessMemory_40e0 {
  strings:
    $key_40e0 = { 17 92 [2] 25 b0 [2] 23 85 [2] 0d 85 [2] 32 99 }

  condition:
    any of them
}