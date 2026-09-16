rule TTP_XOR_WriteProcessMemory_53d4 {
  strings:
    $key_53d4 = { 04 a6 [2] 36 84 [2] 30 b1 [2] 1e b1 [2] 21 ad }

  condition:
    any of them
}