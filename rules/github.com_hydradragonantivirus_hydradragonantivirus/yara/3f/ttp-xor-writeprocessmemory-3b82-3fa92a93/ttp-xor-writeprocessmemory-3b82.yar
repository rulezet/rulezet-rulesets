rule TTP_XOR_WriteProcessMemory_3b82 {
  strings:
    $key_3b82 = { 6c f0 [2] 5e d2 [2] 58 e7 [2] 76 e7 [2] 49 fb }

  condition:
    any of them
}