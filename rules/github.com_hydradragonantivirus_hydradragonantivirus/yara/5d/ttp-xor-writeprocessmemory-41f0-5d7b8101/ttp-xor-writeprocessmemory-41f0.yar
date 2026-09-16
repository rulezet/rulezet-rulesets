rule TTP_XOR_WriteProcessMemory_41f0 {
  strings:
    $key_41f0 = { 16 82 [2] 24 a0 [2] 22 95 [2] 0c 95 [2] 33 89 }

  condition:
    any of them
}