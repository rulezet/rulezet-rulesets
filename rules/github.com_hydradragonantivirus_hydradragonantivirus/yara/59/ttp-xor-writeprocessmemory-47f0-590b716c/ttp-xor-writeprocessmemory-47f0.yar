rule TTP_XOR_WriteProcessMemory_47f0 {
  strings:
    $key_47f0 = { 10 82 [2] 22 a0 [2] 24 95 [2] 0a 95 [2] 35 89 }

  condition:
    any of them
}