rule TTP_XOR_WriteProcessMemory_6b82 {
  strings:
    $key_6b82 = { 3c f0 [2] 0e d2 [2] 08 e7 [2] 26 e7 [2] 19 fb }

  condition:
    any of them
}