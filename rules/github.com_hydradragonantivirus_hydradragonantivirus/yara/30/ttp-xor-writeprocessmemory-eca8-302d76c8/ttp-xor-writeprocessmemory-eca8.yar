rule TTP_XOR_WriteProcessMemory_eca8 {
  strings:
    $key_eca8 = { bb da [2] 89 f8 [2] 8f cd [2] a1 cd [2] 9e d1 }

  condition:
    any of them
}