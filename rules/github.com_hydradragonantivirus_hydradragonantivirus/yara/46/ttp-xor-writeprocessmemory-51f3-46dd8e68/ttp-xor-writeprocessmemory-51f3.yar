rule TTP_XOR_WriteProcessMemory_51f3 {
  strings:
    $key_51f3 = { 06 81 [2] 34 a3 [2] 32 96 [2] 1c 96 [2] 23 8a }

  condition:
    any of them
}