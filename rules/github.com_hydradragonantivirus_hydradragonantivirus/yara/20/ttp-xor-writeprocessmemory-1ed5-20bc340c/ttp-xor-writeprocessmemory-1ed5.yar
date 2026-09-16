rule TTP_XOR_WriteProcessMemory_1ed5 {
  strings:
    $key_1ed5 = { 49 a7 [2] 7b 85 [2] 7d b0 [2] 53 b0 [2] 6c ac }

  condition:
    any of them
}