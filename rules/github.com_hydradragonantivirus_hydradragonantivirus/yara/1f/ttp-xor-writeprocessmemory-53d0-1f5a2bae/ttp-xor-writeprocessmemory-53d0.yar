rule TTP_XOR_WriteProcessMemory_53d0 {
  strings:
    $key_53d0 = { 04 a2 [2] 36 80 [2] 30 b5 [2] 1e b5 [2] 21 a9 }

  condition:
    any of them
}