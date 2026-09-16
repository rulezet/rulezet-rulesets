rule TTP_XOR_WriteProcessMemory_51f5 {
  strings:
    $key_51f5 = { 06 87 [2] 34 a5 [2] 32 90 [2] 1c 90 [2] 23 8c }

  condition:
    any of them
}