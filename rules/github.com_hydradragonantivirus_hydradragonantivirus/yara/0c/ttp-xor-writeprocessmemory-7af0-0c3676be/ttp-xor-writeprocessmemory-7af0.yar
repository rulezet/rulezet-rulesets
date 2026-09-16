rule TTP_XOR_WriteProcessMemory_7af0 {
  strings:
    $key_7af0 = { 2d 82 [2] 1f a0 [2] 19 95 [2] 37 95 [2] 08 89 }

  condition:
    any of them
}