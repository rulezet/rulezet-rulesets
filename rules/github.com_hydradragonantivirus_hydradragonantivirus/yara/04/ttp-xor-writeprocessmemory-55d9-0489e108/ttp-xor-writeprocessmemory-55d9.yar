rule TTP_XOR_WriteProcessMemory_55d9 {
  strings:
    $key_55d9 = { 02 ab [2] 30 89 [2] 36 bc [2] 18 bc [2] 27 a0 }

  condition:
    any of them
}