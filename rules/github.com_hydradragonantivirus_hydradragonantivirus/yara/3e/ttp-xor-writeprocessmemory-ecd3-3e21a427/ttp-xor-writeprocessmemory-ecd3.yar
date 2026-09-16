rule TTP_XOR_WriteProcessMemory_ecd3 {
  strings:
    $key_ecd3 = { bb a1 [2] 89 83 [2] 8f b6 [2] a1 b6 [2] 9e aa }

  condition:
    any of them
}