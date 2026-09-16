rule TTP_XOR_WriteProcessMemory_53f7 {
  strings:
    $key_53f7 = { 04 85 [2] 36 a7 [2] 30 92 [2] 1e 92 [2] 21 8e }

  condition:
    any of them
}