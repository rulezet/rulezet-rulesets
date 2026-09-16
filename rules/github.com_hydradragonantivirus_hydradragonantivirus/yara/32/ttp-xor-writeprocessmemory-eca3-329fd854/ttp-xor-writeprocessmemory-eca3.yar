rule TTP_XOR_WriteProcessMemory_eca3 {
  strings:
    $key_eca3 = { bb d1 [2] 89 f3 [2] 8f c6 [2] a1 c6 [2] 9e da }

  condition:
    any of them
}