rule TTP_XOR_WriteProcessMemory_3da7 {
  strings:
    $key_3da7 = { 6a d5 [2] 58 f7 [2] 5e c2 [2] 70 c2 [2] 4f de }

  condition:
    any of them
}