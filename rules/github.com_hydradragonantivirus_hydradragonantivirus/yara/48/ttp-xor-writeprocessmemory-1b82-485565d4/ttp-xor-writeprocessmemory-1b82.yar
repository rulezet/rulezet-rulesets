rule TTP_XOR_WriteProcessMemory_1b82 {
  strings:
    $key_1b82 = { 4c f0 [2] 7e d2 [2] 78 e7 [2] 56 e7 [2] 69 fb }

  condition:
    any of them
}