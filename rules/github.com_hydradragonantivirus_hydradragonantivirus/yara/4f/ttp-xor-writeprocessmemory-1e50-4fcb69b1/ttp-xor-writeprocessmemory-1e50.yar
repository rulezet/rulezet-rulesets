rule TTP_XOR_WriteProcessMemory_1e50 {
  strings:
    $key_1e50 = { 49 22 [2] 7b 00 [2] 7d 35 [2] 53 35 [2] 6c 29 }

  condition:
    any of them
}