rule TTP_XOR_WriteProcessMemory_ecd5 {
  strings:
    $key_ecd5 = { bb a7 [2] 89 85 [2] 8f b0 [2] a1 b0 [2] 9e ac }

  condition:
    any of them
}