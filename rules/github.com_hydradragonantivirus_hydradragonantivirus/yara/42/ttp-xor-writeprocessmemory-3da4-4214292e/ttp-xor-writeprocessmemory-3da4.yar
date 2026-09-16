rule TTP_XOR_WriteProcessMemory_3da4 {
  strings:
    $key_3da4 = { 6a d6 [2] 58 f4 [2] 5e c1 [2] 70 c1 [2] 4f dd }

  condition:
    any of them
}