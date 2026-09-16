rule TTP_XOR_WriteProcessMemory_5321 {
  strings:
    $key_5321 = { 04 53 [2] 36 71 [2] 30 44 [2] 1e 44 [2] 21 58 }

  condition:
    any of them
}