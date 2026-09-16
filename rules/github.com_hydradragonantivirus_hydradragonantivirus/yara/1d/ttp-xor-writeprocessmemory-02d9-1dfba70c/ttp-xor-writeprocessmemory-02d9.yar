rule TTP_XOR_WriteProcessMemory_02d9 {
  strings:
    $key_02d9 = { 55 ab [2] 67 89 [2] 61 bc [2] 4f bc [2] 70 a0 }

  condition:
    any of them
}