rule TTP_XOR_WriteProcessMemory_10d9 {
  strings:
    $key_10d9 = { 47 ab [2] 75 89 [2] 73 bc [2] 5d bc [2] 62 a0 }

  condition:
    any of them
}