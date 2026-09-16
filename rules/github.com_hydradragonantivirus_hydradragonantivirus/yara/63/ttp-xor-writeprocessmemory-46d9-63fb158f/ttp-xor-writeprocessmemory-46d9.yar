rule TTP_XOR_WriteProcessMemory_46d9 {
  strings:
    $key_46d9 = { 11 ab [2] 23 89 [2] 25 bc [2] 0b bc [2] 34 a0 }

  condition:
    any of them
}