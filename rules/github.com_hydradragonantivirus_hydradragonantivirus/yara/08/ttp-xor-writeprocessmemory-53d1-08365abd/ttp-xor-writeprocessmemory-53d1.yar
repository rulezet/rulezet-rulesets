rule TTP_XOR_WriteProcessMemory_53d1 {
  strings:
    $key_53d1 = { 04 a3 [2] 36 81 [2] 30 b4 [2] 1e b4 [2] 21 a8 }

  condition:
    any of them
}