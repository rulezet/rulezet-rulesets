rule TTP_XOR_WriteProcessMemory_03e0 {
  strings:
    $key_03e0 = { 54 92 [2] 66 b0 [2] 60 85 [2] 4e 85 [2] 71 99 }

  condition:
    any of them
}