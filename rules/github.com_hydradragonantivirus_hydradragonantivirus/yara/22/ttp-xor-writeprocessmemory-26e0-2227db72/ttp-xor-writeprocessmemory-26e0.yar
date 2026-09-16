rule TTP_XOR_WriteProcessMemory_26e0 {
  strings:
    $key_26e0 = { 71 92 [2] 43 b0 [2] 45 85 [2] 6b 85 [2] 54 99 }

  condition:
    any of them
}