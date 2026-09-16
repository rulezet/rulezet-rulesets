rule TTP_XOR_WriteProcessMemory_26d9 {
  strings:
    $key_26d9 = { 71 ab [2] 43 89 [2] 45 bc [2] 6b bc [2] 54 a0 }

  condition:
    any of them
}