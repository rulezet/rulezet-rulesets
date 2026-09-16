rule TTP_XOR_WriteProcessMemory_22e0 {
  strings:
    $key_22e0 = { 75 92 [2] 47 b0 [2] 41 85 [2] 6f 85 [2] 50 99 }

  condition:
    any of them
}