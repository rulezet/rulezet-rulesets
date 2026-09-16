rule TTP_XOR_WriteProcessMemory_78e0 {
  strings:
    $key_78e0 = { 2f 92 [2] 1d b0 [2] 1b 85 [2] 35 85 [2] 0a 99 }

  condition:
    any of them
}