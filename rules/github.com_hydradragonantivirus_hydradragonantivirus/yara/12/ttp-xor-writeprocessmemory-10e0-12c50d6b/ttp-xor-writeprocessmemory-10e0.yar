rule TTP_XOR_WriteProcessMemory_10e0 {
  strings:
    $key_10e0 = { 47 92 [2] 75 b0 [2] 73 85 [2] 5d 85 [2] 62 99 }

  condition:
    any of them
}