rule TTP_XOR_WriteProcessMemory_1e53 {
  strings:
    $key_1e53 = { 49 21 [2] 7b 03 [2] 7d 36 [2] 53 36 [2] 6c 2a }

  condition:
    any of them
}