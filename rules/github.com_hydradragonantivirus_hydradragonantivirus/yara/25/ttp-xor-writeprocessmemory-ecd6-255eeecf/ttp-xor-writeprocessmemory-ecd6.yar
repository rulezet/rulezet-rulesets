rule TTP_XOR_WriteProcessMemory_ecd6 {
  strings:
    $key_ecd6 = { bb a4 [2] 89 86 [2] 8f b3 [2] a1 b3 [2] 9e af }

  condition:
    any of them
}