rule TTP_XOR_WriteProcessMemory_5cd5 {
  strings:
    $key_5cd5 = { 0b a7 [2] 39 85 [2] 3f b0 [2] 11 b0 [2] 2e ac }

  condition:
    any of them
}