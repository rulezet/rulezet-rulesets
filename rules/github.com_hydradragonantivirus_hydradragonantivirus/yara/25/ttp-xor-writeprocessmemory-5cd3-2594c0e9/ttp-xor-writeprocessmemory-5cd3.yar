rule TTP_XOR_WriteProcessMemory_5cd3 {
  strings:
    $key_5cd3 = { 0b a1 [2] 39 83 [2] 3f b6 [2] 11 b6 [2] 2e aa }

  condition:
    any of them
}