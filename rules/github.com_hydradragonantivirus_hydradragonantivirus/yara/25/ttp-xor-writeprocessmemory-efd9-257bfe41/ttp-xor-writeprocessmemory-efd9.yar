rule TTP_XOR_WriteProcessMemory_efd9 {
  strings:
    $key_efd9 = { b8 ab [2] 8a 89 [2] 8c bc [2] a2 bc [2] 9d a0 }

  condition:
    any of them
}