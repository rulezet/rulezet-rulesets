rule TTP_XOR_WriteProcessMemory_33e0 {
  strings:
    $key_33e0 = { 64 92 [2] 56 b0 [2] 50 85 [2] 7e 85 [2] 41 99 }

  condition:
    any of them
}