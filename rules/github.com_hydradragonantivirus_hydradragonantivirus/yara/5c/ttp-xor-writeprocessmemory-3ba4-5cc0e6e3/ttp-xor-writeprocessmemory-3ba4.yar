rule TTP_XOR_WriteProcessMemory_3ba4 {
  strings:
    $key_3ba4 = { 6c d6 [2] 5e f4 [2] 58 c1 [2] 76 c1 [2] 49 dd }

  condition:
    any of them
}