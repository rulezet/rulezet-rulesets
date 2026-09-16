rule TTP_XOR_WriteProcessMemory_77d9 {
  strings:
    $key_77d9 = { 20 ab [2] 12 89 [2] 14 bc [2] 3a bc [2] 05 a0 }

  condition:
    any of them
}