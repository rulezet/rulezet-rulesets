rule TTP_XOR_WriteProcessMemory_2fd9 {
  strings:
    $key_2fd9 = { 78 ab [2] 4a 89 [2] 4c bc [2] 62 bc [2] 5d a0 }

  condition:
    any of them
}