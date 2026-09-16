rule TTP_XOR_WriteProcessMemory_6ba4 {
  strings:
    $key_6ba4 = { 3c d6 [2] 0e f4 [2] 08 c1 [2] 26 c1 [2] 19 dd }

  condition:
    any of them
}