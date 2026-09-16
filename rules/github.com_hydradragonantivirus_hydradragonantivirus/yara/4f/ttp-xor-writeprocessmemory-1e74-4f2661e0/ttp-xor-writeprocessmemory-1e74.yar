rule TTP_XOR_WriteProcessMemory_1e74 {
  strings:
    $key_1e74 = { 49 06 [2] 7b 24 [2] 7d 11 [2] 53 11 [2] 6c 0d }

  condition:
    any of them
}