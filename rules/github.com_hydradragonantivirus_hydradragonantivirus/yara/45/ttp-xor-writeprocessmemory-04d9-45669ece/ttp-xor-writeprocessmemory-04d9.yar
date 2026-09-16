rule TTP_XOR_WriteProcessMemory_04d9 {
  strings:
    $key_04d9 = { 53 ab [2] 61 89 [2] 67 bc [2] 49 bc [2] 76 a0 }

  condition:
    any of them
}