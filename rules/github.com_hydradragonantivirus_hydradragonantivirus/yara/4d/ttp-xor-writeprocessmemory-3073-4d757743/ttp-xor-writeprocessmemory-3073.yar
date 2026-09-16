rule TTP_XOR_WriteProcessMemory_3073 {
  strings:
    $key_3073 = { 67 01 [2] 55 23 [2] 53 16 [2] 7d 16 [2] 42 0a }

  condition:
    any of them
}