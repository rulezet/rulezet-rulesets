rule TTP_XOR_WriteProcessMemory_32d9 {
  strings:
    $key_32d9 = { 65 ab [2] 57 89 [2] 51 bc [2] 7f bc [2] 40 a0 }

  condition:
    any of them
}