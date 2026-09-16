rule TTP_XOR_WriteProcessMemory_7d21 {
  strings:
    $key_7d21 = { 2a 53 [2] 18 71 [2] 1e 44 [2] 30 44 [2] 0f 58 }

  condition:
    any of them
}