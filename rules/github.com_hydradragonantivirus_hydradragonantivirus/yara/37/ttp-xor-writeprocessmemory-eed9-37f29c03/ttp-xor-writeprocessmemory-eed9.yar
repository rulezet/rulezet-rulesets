rule TTP_XOR_WriteProcessMemory_eed9 {
  strings:
    $key_eed9 = { b9 ab [2] 8b 89 [2] 8d bc [2] a3 bc [2] 9c a0 }

  condition:
    any of them
}