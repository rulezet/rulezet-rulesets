rule TTP_XOR_WriteProcessMemory_e8f0 {
  strings:
    $key_e8f0 = { bf 82 [2] 8d a0 [2] 8b 95 [2] a5 95 [2] 9a 89 }

  condition:
    any of them
}