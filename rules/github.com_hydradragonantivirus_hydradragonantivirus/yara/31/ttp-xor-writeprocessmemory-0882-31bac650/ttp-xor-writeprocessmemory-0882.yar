rule TTP_XOR_WriteProcessMemory_0882 {
  strings:
    $key_0882 = { 5f f0 [2] 6d d2 [2] 6b e7 [2] 45 e7 [2] 7a fb }

  condition:
    any of them
}