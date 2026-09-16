rule TTP_XOR_WriteProcessMemory_08f0 {
  strings:
    $key_08f0 = { 5f 82 [2] 6d a0 [2] 6b 95 [2] 45 95 [2] 7a 89 }

  condition:
    any of them
}