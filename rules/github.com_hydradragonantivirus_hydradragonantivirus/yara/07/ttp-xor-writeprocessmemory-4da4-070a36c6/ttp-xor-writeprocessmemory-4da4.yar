rule TTP_XOR_WriteProcessMemory_4da4 {
  strings:
    $key_4da4 = { 1a d6 [2] 28 f4 [2] 2e c1 [2] 00 c1 [2] 3f dd }

  condition:
    any of them
}