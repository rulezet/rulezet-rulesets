rule TTP_XOR_WriteProcessMemory_1ba4 {
  strings:
    $key_1ba4 = { 4c d6 [2] 7e f4 [2] 78 c1 [2] 56 c1 [2] 69 dd }

  condition:
    any of them
}