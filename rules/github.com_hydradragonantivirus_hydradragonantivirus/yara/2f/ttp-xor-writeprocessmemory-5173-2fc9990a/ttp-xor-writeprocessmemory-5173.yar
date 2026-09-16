rule TTP_XOR_WriteProcessMemory_5173 {
  strings:
    $key_5173 = { 06 01 [2] 34 23 [2] 32 16 [2] 1c 16 [2] 23 0a }

  condition:
    any of them
}