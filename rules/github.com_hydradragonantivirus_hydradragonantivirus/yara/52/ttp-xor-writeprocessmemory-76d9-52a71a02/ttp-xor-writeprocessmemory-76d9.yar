rule TTP_XOR_WriteProcessMemory_76d9 {
  strings:
    $key_76d9 = { 21 ab [2] 13 89 [2] 15 bc [2] 3b bc [2] 04 a0 }

  condition:
    any of them
}