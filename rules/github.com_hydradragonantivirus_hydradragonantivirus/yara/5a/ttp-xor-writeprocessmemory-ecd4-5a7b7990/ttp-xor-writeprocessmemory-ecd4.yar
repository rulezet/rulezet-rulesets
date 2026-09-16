rule TTP_XOR_WriteProcessMemory_ecd4 {
  strings:
    $key_ecd4 = { bb a6 [2] 89 84 [2] 8f b1 [2] a1 b1 [2] 9e ad }

  condition:
    any of them
}