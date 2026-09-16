rule TTP_XOR_WriteProcessMemory_0ba4 {
  strings:
    $key_0ba4 = { 5c d6 [2] 6e f4 [2] 68 c1 [2] 46 c1 [2] 79 dd }

  condition:
    any of them
}