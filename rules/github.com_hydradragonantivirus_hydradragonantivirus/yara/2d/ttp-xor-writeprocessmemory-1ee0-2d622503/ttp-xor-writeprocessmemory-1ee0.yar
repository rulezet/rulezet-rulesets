rule TTP_XOR_WriteProcessMemory_1ee0 {
  strings:
    $key_1ee0 = { 49 92 [2] 7b b0 [2] 7d 85 [2] 53 85 [2] 6c 99 }

  condition:
    any of them
}