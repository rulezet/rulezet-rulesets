rule TTP_XOR_WriteProcessMemory_16e0 {
  strings:
    $key_16e0 = { 41 92 [2] 73 b0 [2] 75 85 [2] 5b 85 [2] 64 99 }

  condition:
    any of them
}