rule TTP_XOR_WriteProcessMemory_6fe0 {
  strings:
    $key_6fe0 = { 38 92 [2] 0a b0 [2] 0c 85 [2] 22 85 [2] 1d 99 }

  condition:
    any of them
}