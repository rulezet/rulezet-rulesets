rule TTP_XOR_WriteProcessMemory_1e72 {
  strings:
    $key_1e72 = { 49 00 [2] 7b 22 [2] 7d 17 [2] 53 17 [2] 6c 0b }

  condition:
    any of them
}