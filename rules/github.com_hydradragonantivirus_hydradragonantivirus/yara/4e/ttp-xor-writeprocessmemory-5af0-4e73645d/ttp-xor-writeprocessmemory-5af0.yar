rule TTP_XOR_WriteProcessMemory_5af0 {
  strings:
    $key_5af0 = { 0d 82 [2] 3f a0 [2] 39 95 [2] 17 95 [2] 28 89 }

  condition:
    any of them
}