rule TTP_XOR_WriteProcessMemory_2da4 {
  strings:
    $key_2da4 = { 7a d6 [2] 48 f4 [2] 4e c1 [2] 60 c1 [2] 5f dd }

  condition:
    any of them
}