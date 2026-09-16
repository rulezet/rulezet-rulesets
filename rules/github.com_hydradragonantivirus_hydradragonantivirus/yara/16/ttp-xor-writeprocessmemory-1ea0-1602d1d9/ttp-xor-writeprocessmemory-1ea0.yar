rule TTP_XOR_WriteProcessMemory_1ea0 {
  strings:
    $key_1ea0 = { 49 d2 [2] 7b f0 [2] 7d c5 [2] 53 c5 [2] 6c d9 }

  condition:
    any of them
}