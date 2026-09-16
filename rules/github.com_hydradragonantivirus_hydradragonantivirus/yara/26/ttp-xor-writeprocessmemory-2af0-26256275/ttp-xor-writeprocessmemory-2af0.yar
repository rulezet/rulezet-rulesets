rule TTP_XOR_WriteProcessMemory_2af0 {
  strings:
    $key_2af0 = { 7d 82 [2] 4f a0 [2] 49 95 [2] 67 95 [2] 58 89 }

  condition:
    any of them
}