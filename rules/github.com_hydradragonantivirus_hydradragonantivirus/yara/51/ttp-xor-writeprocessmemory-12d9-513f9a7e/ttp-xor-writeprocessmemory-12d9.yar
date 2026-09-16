rule TTP_XOR_WriteProcessMemory_12d9 {
  strings:
    $key_12d9 = { 45 ab [2] 77 89 [2] 71 bc [2] 5f bc [2] 60 a0 }

  condition:
    any of them
}