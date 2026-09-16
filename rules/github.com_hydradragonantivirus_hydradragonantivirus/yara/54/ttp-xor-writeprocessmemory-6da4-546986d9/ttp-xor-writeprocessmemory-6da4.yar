rule TTP_XOR_WriteProcessMemory_6da4 {
  strings:
    $key_6da4 = { 3a d6 [2] 08 f4 [2] 0e c1 [2] 20 c1 [2] 1f dd }

  condition:
    any of them
}