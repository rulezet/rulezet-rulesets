rule TTP_XOR_WriteProcessMemory_3cd9 {
  strings:
    $key_3cd9 = { 6b ab [2] 59 89 [2] 5f bc [2] 71 bc [2] 4e a0 }

  condition:
    any of them
}