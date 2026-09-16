rule TTP_XOR_WriteProcessMemory_40f5 {
  strings:
    $key_40f5 = { 17 87 [2] 25 a5 [2] 23 90 [2] 0d 90 [2] 32 8c }

  condition:
    any of them
}