rule TTP_XOR_WriteProcessMemory_08e0 {
  strings:
    $key_08e0 = { 5f 92 [2] 6d b0 [2] 6b 85 [2] 45 85 [2] 7a 99 }

  condition:
    any of them
}