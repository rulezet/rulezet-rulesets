rule TTP_XOR_WriteProcessMemory_6ff0 {
  strings:
    $key_6ff0 = { 38 82 [2] 0a a0 [2] 0c 95 [2] 22 95 [2] 1d 89 }

  condition:
    any of them
}