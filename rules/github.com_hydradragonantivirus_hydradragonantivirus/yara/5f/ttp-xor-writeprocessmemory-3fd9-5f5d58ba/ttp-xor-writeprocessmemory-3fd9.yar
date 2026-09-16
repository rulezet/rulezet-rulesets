rule TTP_XOR_WriteProcessMemory_3fd9 {
  strings:
    $key_3fd9 = { 68 ab [2] 5a 89 [2] 5c bc [2] 72 bc [2] 4d a0 }

  condition:
    any of them
}